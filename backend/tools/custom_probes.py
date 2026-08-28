"""Built-in dynamic security testing engine.

Runs entirely against the sandboxed application's loopback endpoint:
- source-derived route discovery + live status mapping
- security header / cookie flag checks
- HTTP method abuse (TRACE/OPTIONS/PUT/DELETE)
- missing-authentication checks on auth-sensitive routes
- controlled alternate-object (IDOR/BOLA) checks
- reflected-content / XSS checks
- SQL-injection smoke tests (error/boolean based, benign payloads)
- command-injection smoke tests (harmless marker command)
- path-traversal checks (read-only, look for marker files)
- debug/config/env endpoint exposure checks
- error-based input-validation probing (bounded)

Every dynamic finding carries a machine-readable `reproduction` dict so the
verification engine can replay it before/after a patch. All requests go
through `probe()` which hard-refuses non-loopback targets.
"""
from __future__ import annotations

import re
import time
from typing import Any

from events import log
from services.probes.http import discover_routes, probe, request_summary
from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HTTP Strict Transport Security (HSTS) is missing",
    "Content-Security-Policy": "Content-Security-Policy is missing",
    "X-Content-Type-Options": "X-Content-Type-Options (nosniff) is missing",
    "X-Frame-Options": "X-Frame-Options is missing (clickjacking risk)",
    "Referrer-Policy": "Referrer-Policy is missing",
}

MAX_ROUTES = 60
MAX_REQUESTS = 420
MUTATIONS = ["'", '"', "%00", "1 OR 1=1", "<script>alert(1)</script>", "a" * 500, "../etc/passwd", "{{7*7}}", "${{7*7}}", "\\", "%27 OR '1'='1"]
SQLI_PAYLOADS = ["' OR '1'='1", '" OR ""="', "1 OR 1=1 --", "' UNION SELECT 1--", "1;SELECT 1"]
CMDI_MARKER = "SFCMDIPWNED"
DEBUG_PATHS = ["/api/debug", "/api/debug/env", "/api/config", "/api/env", "/debug", "/api/admin", "/admin", "/actuator", "/actuator/env"]


class CustomProbeAdapter(ToolAdapter):
    name = "custom_probes"
    display_name = "Dynamic Probes"

    def detect(self) -> bool:
        return True

    def install_hint(self) -> str:
        return ""

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        base_url = ctx.runtime.get("base_url")
        if not base_url:
            ctx.add_limitation("Dynamic testing skipped: application did not start")
            return []
        findings: list[dict[str, Any]] = []
        requests_sent = 0

        def budget() -> bool:
            nonlocal requests_sent
            requests_sent += 1
            return requests_sent <= MAX_REQUESTS

        def repro(method: str, path: str, expect: dict[str, Any] | None = None, params: dict[str, Any] | None = None, body: str | None = None) -> dict[str, Any]:
            return {"method": method, "path": path, "params": params or {}, "body": body, "expect": expect, "steps": [f"{method} {path}"], "tool": "dynamic"}

        # ---- 1. route discovery -------------------------------------------------
        source_routes = discover_routes(ctx.working)
        live_routes: list[dict[str, Any]] = []
        log(ctx.scan_id, f"Route discovery: {len(source_routes)} route candidates in source")
        for route in source_routes[:MAX_ROUTES]:
            if not budget():
                break
            path = route["path"]
            if "{" in path:
                path = re.sub(r"\{[^}]+\}", "1", path)
            url = base_url.rstrip("/") + path
            try:
                resp = probe("GET", url, timeout_s=4)
                route["status"] = resp.status_code
                route["url"] = url
                live_routes.append(route)
                time.sleep(0.03)
            except Exception:
                continue
        live = [r for r in live_routes if r.get("status", 0) < 500]
        if live:
            log(ctx.scan_id, f"{len(live)} routes reachable over HTTP")

        # ---- 2. security headers (aggregated) -------------------------------------
        if live:
            sample = next(r for r in live)
            try:
                resp = probe("GET", sample["url"], timeout_s=5)
                missing_headers: dict[str, str] = {}
                for h, msg in REQUIRED_SECURITY_HEADERS.items():
                    if h.lower() not in {k.lower() for k in resp.headers}:
                        missing_headers[h] = msg
                for c in resp.headers.get_list("set-cookie"):
                    if "httponly" not in c.lower():
                        findings.append(make_finding(
                            title="Cookie missing HttpOnly flag",
                            category="configuration", severity="MEDIUM", confidence=0.8, source="dynamic",
                            affected_component=sample["path"],
                            description=f"Set-Cookie header lacks HttpOnly: {c[:120]}",
                            evidence={"tool": "dynamic", "target": sample["url"], "set_cookie": c[:200], "request": f"GET {sample['url']}", "response": str(resp.status_code)},
                            reproduction=repro("GET", sample["path"]),
                        ))
                    if "secure" not in c.lower():
                        findings.append(make_finding(
                            title="Cookie missing Secure flag",
                            category="configuration", severity="MEDIUM", confidence=0.8, source="dynamic",
                            affected_component=sample["path"],
                            description=f"Set-Cookie header lacks Secure: {c[:120]}",
                            evidence={"tool": "dynamic", "target": sample["url"], "set_cookie": c[:200]},
                            reproduction=repro("GET", sample["path"]),
                        ))
                if missing_headers:
                    findings.append(make_finding(
                        title="Missing HTTP security headers",
                        category="configuration", severity="LOW", confidence=0.9, source="dynamic",
                        affected_component=sample["path"],
                        description="; ".join(missing_headers.values()) + ".",
                        why_it_matters="Missing security headers weaken browser-side protections (XSS, clickjacking, MIME sniffing).",
                        evidence={"tool": "dynamic", "target": sample["url"], "missing": list(missing_headers.keys()), "response": request_summary(resp)},
                        reproduction=repro("GET", sample["path"]),
                    ))
            except Exception:
                pass

        # ---- 3. method abuse ---------------------------------------------------------
        if live:
            checked: set[str] = set()
            for route in live[:20]:
                url, path = route["url"], route["path"]
                if url in checked:
                    continue
                checked.add(url)
                try:
                    tr = probe("TRACE", url, timeout_s=4)
                    if tr.status_code == 200 and "TRACE" in (tr.text or "").upper()[:500]:
                        findings.append(make_finding(
                            title="TRACE method enabled (cross-site tracing risk)",
                            category="api_security", severity="LOW", confidence=0.85, source="dynamic",
                            affected_component=path,
                            description=f"TRACE is enabled on {path}.",
                            evidence={"tool": "dynamic", "target": url, "request": f"TRACE {url}", "response": request_summary(tr)},
                            reproduction=repro("TRACE", path, {"status": 200}),
                        ))
                    op = probe("OPTIONS", url, timeout_s=4)
                    if op.status_code == 200:
                        allow = (op.headers.get("allow") or "").upper()
                        if allow and any(m in allow for m in ("PUT", "DELETE", "PATCH")):
                            findings.append(make_finding(
                                title="Excessive HTTP methods allowed",
                                category="api_security", severity="LOW", confidence=0.6, source="dynamic",
                                affected_component=path,
                                description=f"OPTIONS on {path} advertises: {allow}",
                                evidence={"tool": "dynamic", "target": url, "request": f"OPTIONS {url}", "response": request_summary(op)},
                                reproduction=repro("OPTIONS", path),
                            ))
                    time.sleep(0.03)
                except Exception:
                    continue

        # ---- 4. missing auth + IDOR ----------------------------------------------------
        auth_candidates = [r for r in live if r.get("auth_hint")][:15]
        idor_candidates: list[dict[str, Any]] = []
        for route in auth_candidates:
            if not budget():
                break
            url, path = route["url"], route["path"]
            try:
                resp = probe("GET", url, timeout_s=5)
                if resp.status_code == 200:
                    body = (resp.text or "")[:4000]
                    if re.search(r"(?i)(login|signin|auth|admin)", path) and "password" not in body.lower() and re.search(r"(?i)(email|user|token|key)", body):
                        findings.append(make_finding(
                            title="Missing authentication on sensitive route",
                            category="authentication", severity="HIGH", confidence=0.7, source="dynamic",
                            affected_component=path,
                            affected_file=route.get("source_file", ""),
                            line_start=route.get("line"),
                            description=f"Route {path} returns data without authentication.",
                            why_it_matters="Sensitive endpoints reachable without authentication bypass access control.",
                            evidence={"tool": "dynamic", "target": url, "request": f"GET {url}", "response": request_summary(resp)},
                            reproduction=repro("GET", path, {"status": 200}),
                        ))
                    if re.search(r"(?i)user|account|profile|order|item|document|file|post", path):
                        idor_candidates.append(route)
                time.sleep(0.03)
            except Exception:
                continue

        for route in idor_candidates[:10]:
            if not budget():
                break
            path, url = route["path"], route["url"]
            variants = []
            base = re.sub(r"/\d+$", "", url.rstrip("/"))
            if base != url:
                variants.append((base + "/1", base + "/2"))
            variants.append((url + "?id=1", url + "?id=2"))
            try:
                for a_url, b_url in variants:
                    a = probe("GET", a_url, timeout_s=5)
                    b = probe("GET", b_url, timeout_s=5)
                    if a.status_code == 200 and b.status_code == 200:
                        ta, tb = (a.text or "")[:600], (b.text or "")[:600]
                        if ta != tb and ta and tb:
                            findings.append(make_finding(
                                title="Broken object-level authorization (IDOR/BOLA)",
                                category="authorization", severity="HIGH", confidence=0.8, source="dynamic",
                                affected_component=path,
                                affected_file=route.get("source_file", ""),
                                line_start=route.get("line"),
                                description=f"Alternate object identifiers return different resources without authentication ({a_url} vs {b_url}).",
                                why_it_matters="Users can read others' objects - classic IDOR. Server must enforce ownership.",
                                evidence={"tool": "dynamic", "target": a_url, "request": f"GET {a_url} and GET {b_url}", "response": {"id_1": ta[:300], "id_2": tb[:300]}},
                                reproduction=repro("GET", _path_of(a_url, base_url), {"status": 200}, params={"id": "1"}),
                            ))
                            break
                    time.sleep(0.03)
            except Exception:
                continue

        # ---- 5. reflected content / XSS ------------------------------------------------
        for route in live[:15]:
            if not budget():
                break
            path, url = route["path"], route["url"]
            if re.search(r"(?i)(image|css|js|favicon|\.png|\.ico|\.js$|\.css$)", path):
                continue
            payload = "<script>alert(document.domain)</script>"
            try:
                resp = probe("GET", url, params={"q": payload, "name": payload, "search": payload, "id": payload}, timeout_s=5)
                ctype = (resp.headers.get("content-type") or "")
                if payload in (resp.text or "") and "json" not in ctype:
                    findings.append(make_finding(
                        title="Reflected XSS (unescaped user input in response)",
                        category="xss", severity="HIGH", confidence=0.75, source="dynamic",
                        affected_component=path,
                        affected_file=route.get("source_file", ""),
                        line_start=route.get("line"),
                        description=f"GET {url} reflects the raw payload unescaped in an HTML response.",
                        why_it_matters="Reflected, unescaped input allows script execution in a victim's browser.",
                        evidence={"tool": "dynamic", "target": url, "request": f"GET {url}?q={payload[:40]}", "response": request_summary(resp)},
                        reproduction=repro("GET", path, {"contains": payload}, params={"q": payload}),
                    ))
                elif payload in (resp.text or "") and "json" in ctype:
                    findings.append(make_finding(
                        title="User input reflected in API response",
                        category="xss", severity="LOW", confidence=0.5, source="dynamic",
                        affected_component=path,
                        description=f"GET {url} reflects input in a JSON response - verify the frontend escapes it before rendering (potential stored/reflected XSS).",
                        evidence={"tool": "dynamic", "target": url, "request": f"GET {url}?q={payload[:40]}", "response": request_summary(resp)},
                        reproduction=repro("GET", path, {"contains": payload}, params={"q": payload}),
                        provenance="Potential",
                    ))
                time.sleep(0.03)
            except Exception:
                continue

        # ---- 6. SQL injection smoke -------------------------------------------------------
        for route in live[:12]:
            if not budget():
                break
            path, url = route["path"], route["url"]
            if not re.search(r"(?i)(search|query|q|find|lookup|user|name|id|filter)", path + " " + url):
                continue
            try:
                baseline = probe("GET", url, params={"q": "baseline", "name": "baseline", "id": "1"}, timeout_s=5)
                baseline_len = len(baseline.text or "")
                for payload in SQLI_PAYLOADS:
                    if not budget():
                        break
                    try:
                        resp = probe("GET", url, params={"q": payload, "name": payload, "id": payload}, timeout_s=5)
                        body = resp.text or ""
                        if resp.status_code == 500:
                            findings.append(make_finding(
                                title="Potential SQL injection (error-based)",
                                category="injection", severity="HIGH", confidence=0.55, source="dynamic",
                                affected_component=path,
                                affected_file=route.get("source_file", ""),
                                line_start=route.get("line"),
                                description=f"GET {url} returns HTTP 500 for SQL metacharacters ({payload[:40]!r}).",
                                why_it_matters="SQL metacharacters triggering errors often indicate string-built queries.",
                                evidence={"tool": "dynamic", "target": url, "request": f"GET {url}?q={payload[:40]}", "response": request_summary(resp)},
                                reproduction=repro("GET", path, {"status": 500}, params={"q": payload}),
                                provenance="Potential",
                            ))
                            break
                        if baseline_status_ok(resp.status_code) and baseline_len and len(body) > baseline_len * 2:
                            findings.append(make_finding(
                                title="Potential SQL injection (boolean-based response change)",
                                category="injection", severity="HIGH", confidence=0.5, source="dynamic",
                                affected_component=path,
                                affected_file=route.get("source_file", ""),
                                line_start=route.get("line"),
                                description=f"Payload {payload[:40]!r} changes response size dramatically ({baseline_len} → {len(body)} chars).",
                                why_it_matters="Boolean-based differences indicate unparameterized queries.",
                                evidence={"tool": "dynamic", "target": url, "request": f"GET {url}?q={payload[:40]}", "response": request_summary(resp)},
                                reproduction=repro("GET", path, {"contains": payload[:20]}, params={"q": payload}),
                                provenance="Potential",
                            ))
                            break
                        time.sleep(0.02)
                    except Exception:
                        break
            except Exception:
                continue

        # ---- 7. command injection smoke ----------------------------------------------------
        # Detect command-execution sinks from source analysis
        cmdi_param_names = ("cmd", "command", "host", "ping", "exec", "run", "shell", "query", "cmdline", "cmdstr", "cmdStr", "input", "data")
        for route in live[:12]:
            if not budget():
                break
            path, url = route["path"], route["url"]
            # Match routes with command-related keywords OR routes that have source-detected exec sinks
            has_cmdi_hint = bool(re.search(r"(?i)(ping|exec|run|cmd|command|host|shell|cmdline)", path))
            has_source_sink = any(s in (route.get("source_snippet", "") or "").lower() for s in
                                 ("exec(", "exec(", "child_process", "subprocess", "os.system", "shell=True"))
            if not has_cmdi_hint and not has_source_sink:
                continue
            # Try all plausible parameter names
            try:
                baseline = probe("GET", url, params={"cmd": "echo test", "host": "127.0.0.1"}, timeout_s=6)
                base_body = baseline.text or ""
                for param in ("cmd", "command", "host"):
                    if CMDI_MARKER in base_body:
                        break
                    for payload in (f"echo {CMDI_MARKER}", f"127.0.0.1 & echo {CMDI_MARKER}", f"127.0.0.1; echo {CMDI_MARKER}", f"127.0.0.1 && echo {CMDI_MARKER}"):
                        if not budget():
                            break
                        try:
                            resp = probe("GET", url, params={param: payload}, timeout_s=6)
                            if CMDI_MARKER in (resp.text or "") and CMDI_MARKER not in base_body:
                                findings.append(make_finding(
                                    title="Command injection (confirmed)",
                                    category="injection", severity="CRITICAL", confidence=0.9, source="dynamic",
                                    affected_component=path,
                                    affected_file=route.get("source_file", ""),
                                    line_start=route.get("line"),
                                    description=f"GET {url} executes the injected marker `echo {CMDI_MARKER}` via parameter {param} - command output is returned in the response.",
                                    why_it_matters="Arbitrary command execution on the server is a critical compromise primitive.",
                                    evidence={"tool": "dynamic", "target": url, "request": f"GET {url}?{param}={payload[:50]}", "response": request_summary(resp)},
                                    reproduction=repro("GET", path, {"contains": CMDI_MARKER}, params={param: payload}),
                                    provenance="Confirmed",
                                ))
                                break
                            time.sleep(0.02)
                        except Exception:
                            break
                    else:
                        continue
                    break
            except Exception:
                continue

        # ---- 8. path traversal -------------------------------------------------------------
        for route in live[:12]:
            if not budget():
                break
            path, url = route["path"], route["url"]
            if not re.search(r"(?i)(file|download|read|name|path|image|doc)", path):
                continue
            try:
                try:
                    base = probe("GET", url, params={"name": "welcome.txt", "file": "welcome.txt", "path": "welcome.txt"}, timeout_s=5)
                except Exception:
                    base = None
                for payload, marker in (("../../../../etc/passwd", "root:"), ("../../../../../../Windows/win.ini", "[fonts]"), ("../../package.json", "\"express\""), ("....//....//etc/passwd", "root:")):
                    if not budget():
                        break
                    try:
                        resp = probe("GET", url, params={"name": payload, "file": payload, "path": payload}, timeout_s=5)
                        body = resp.text or ""
                        if marker in body:
                            findings.append(make_finding(
                                title="Path traversal (confirmed file read)",
                                category="file_security", severity="CRITICAL", confidence=0.9, source="dynamic",
                                affected_component=path,
                                affected_file=route.get("source_file", ""),
                                line_start=route.get("line"),
                                description=f"GET {url} with {payload!r} returns the contents of {marker if marker=='root:' else 'win.ini'} (marker {marker!r} found).",
                                why_it_matters="Arbitrary file read can expose source, configs and credentials.",
                                evidence={"tool": "dynamic", "target": url, "request": f"GET {url}?name={payload}", "response": request_summary(resp)},
                                reproduction=repro("GET", path, {"contains": marker}, params={"name": payload}),
                                provenance="Confirmed",
                            ))
                            break
                        time.sleep(0.02)
                    except Exception:
                        break
            except Exception:
                continue

        # ---- 9. SSTI (Server-Side Template Injection) ----------------------------------------
        SSTI_PAYLOADS = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{config}}", "SECRET"),
            ("{{''.__class__.__mro__[1].__subclasses__()}}", "<class"),
        ]
        for route in live[:15]:
            if not budget():
                break
            path, url = route["path"], route["url"]
            if re.search(r"(?i)(image|css|js|favicon|\.png|\.ico|\.js$|\.css$)", path):
                continue
            # Check source for template/eval sinks
            snippet = (route.get("source_snippet", "") or "").lower()
            has_ssti_hint = bool(re.search(r"(?i)(render|template|eval| tmpl|engine)", path + " " + snippet))
            # Also check for generic query routes that might accept templates
            has_generic_input = bool(re.search(r"(?i)(q=|name=|input=|tmpl=|template=|text=)", path))
            if not has_ssti_hint and not has_generic_input:
                continue
            for payload, marker in SSTI_PAYLOADS:
                if not budget():
                    break
                try:
                    for param in ("tmpl", "template", "q", "name", "input", "text"):
                        resp = probe("GET", url, params={param: payload}, timeout_s=5)
                        body = resp.text or ""
                        if marker in body and marker not in (probe("GET", url, params={param: "safe"}, timeout_s=5).text or ""):
                            findings.append(make_finding(
                                title="Server-side template injection (SSTI) (confirmed)",
                                category="injection", severity="CRITICAL", confidence=0.85, source="dynamic",
                                affected_component=path,
                                affected_file=route.get("source_file", ""),
                                line_start=route.get("line"),
                                description=f"GET {url}?{param}={payload} evaluates template expressions server-side (marker {marker!r} found).",
                                why_it_matters="SSTI allows arbitrary code execution through template engine abuse.",
                                evidence={"tool": "dynamic", "target": url, "request": f"GET {url}?{param}={payload}", "response": request_summary(resp)},
                                reproduction=repro("GET", path, {"contains": marker}, params={param: payload}),
                                provenance="Confirmed",
                            ))
                            break
                        time.sleep(0.02)
                except Exception:
                    continue

        # ---- 10. debug / config exposure ------------------------------------------------------
        for dpath in DEBUG_PATHS:
            if not budget():
                break
            try:
                resp = probe("GET", base_url.rstrip("/") + dpath, timeout_s=4)
                if resp.status_code == 200:
                    body = (resp.text or "")[:3000]
                    if re.search(r"(?i)(GROQ_API_KEY|API_KEY|SECRET|PASSWORD|DATABASE_URL|PATH=)", body):
                        findings.append(make_finding(
                            title="Debug/environment endpoint exposes sensitive data",
                            category="configuration", severity="HIGH", confidence=0.85, source="dynamic",
                            affected_component=dpath,
                            description=f"GET {dpath} returns environment/config data including sensitive keys.",
                            why_it_matters="Exposed debug endpoints leak secrets and internals to attackers.",
                            evidence={"tool": "dynamic", "target": dpath, "request": f"GET {dpath}", "response": request_summary(resp)},
                            reproduction=repro("GET", dpath, {"status": 200}),
                        ))
                    elif re.search(r"(?i)(env|config|debug|status|version)", body):
                        findings.append(make_finding(
                            title="Debug/configuration endpoint exposed",
                            category="configuration", severity="MEDIUM", confidence=0.6, source="dynamic",
                            affected_component=dpath,
                            description=f"GET {dpath} returns informational config data.",
                            evidence={"tool": "dynamic", "target": dpath, "request": f"GET {dpath}", "response": request_summary(resp)},
                            reproduction=repro("GET", dpath, {"status": 200}),
                        ))
                time.sleep(0.02)
            except Exception:
                continue

        # ---- 10. error-based input validation ------------------------------------------------
        input_routes = [r for r in live if r.get("status", 0) in (200, 400, 422)][:10]
        for route in input_routes:
            if not budget():
                break
            url, path = route["url"], route["path"]
            try:
                baseline = probe("GET", url, timeout_s=5)
                for payload in MUTATIONS:
                    if not budget():
                        break
                    try:
                        mutated = probe("GET", url, params={"q": payload, "id": payload, "name": payload}, timeout_s=4)
                        if mutated.status_code == 500:
                            findings.append(make_finding(
                                title="Unhandled exception on malformed input",
                                category="reliability", severity="MEDIUM", confidence=0.65, source="dynamic",
                                affected_component=path,
                                affected_file=route.get("source_file", ""),
                                line_start=route.get("line"),
                                description=f"GET {url} returns HTTP 500 with malformed parameters (payload: {payload[:40]!r}).",
                                why_it_matters="Unhandled exceptions can leak stack traces and signal missing input validation.",
                                evidence={"tool": "dynamic", "target": url, "request": f"GET {url}?q={payload[:60]}", "response": request_summary(mutated)},
                                reproduction=repro("GET", path, {"status": 500}, params={"q": payload}),
                            ))
                            break
                        time.sleep(0.02)
                    except Exception:
                        break
            except Exception:
                continue

        return findings


def baseline_status_ok(status: int) -> bool:
    return status in (200, 201, 400)


def _path_of(url: str, base_url: str) -> str:
    return "/" + url.replace(base_url.rstrip("/"), "").lstrip("/")
