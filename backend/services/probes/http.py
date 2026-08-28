"""Loopback-restricted HTTP probe client + source-level route discovery.

Hard enforcement: every probe URL must resolve to a loopback address
(127.0.0.1 / ::1 / localhost). External targets are rejected at the
client layer, not just in the UI.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def enforce_loopback(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http(s) targets are allowed: {url}")
    host = parsed.hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Target is not loopback: {host!r}. Testing is restricted to the sandboxed project.")
    return url


def probe(method: str, url: str, timeout_s: float = 5.0, **kwargs: Any) -> httpx.Response:
    """Send a probe request, refusing any non-loopback target."""
    enforce_loopback(url)
    client = httpx.Client(
        timeout=timeout_s,
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": "SentinelForge-Probe/1.0", "Accept": "*/*"},
    )
    try:
        resp = client.request(method, url, **kwargs)
        return resp
    finally:
        client.close()


def request_summary(resp: httpx.Response, body_limit: int = 2000) -> dict[str, Any]:
    body = (resp.text or "")[:body_limit]
    return {
        "status": resp.status_code,
        "headers": {k: v for k, v in resp.headers.items()},
        "body_preview": body,
    }


def _safe_is_file(path: Path) -> bool:
    """Check if a path is a regular file, handling broken symlinks."""
    try:
        return path.is_file()
    except OSError:
        return False


# --- source-level route discovery ------------------------------------------

ROUTE_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # express-style: app.get('/path', ...)  / router.get(...)
    ("js", "express", re.compile(r"(?m)^\s*\w*(?:\.|router\.|app\.)(get|post|put|patch|delete|all|use)\s*\(\s*['\"`]([^'\"`]+)['\"`]")),
    ("js", "express-var", re.compile(r"(?m)\b(app|router|route)\.(get|post|put|patch|delete|all)\s*\(\s*(['\"])([^'\"]+)\3")),
    ("py", "flask", re.compile(r"(?m)@\w*\.route\s*\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?")),
    ("py", "fastapi", re.compile(r"(?m)@\w+\.(?:get|post|put|patch|delete|options)\s*\(\s*['\"]([^'\"]+)['\"]")),
    ("py", "django", re.compile(r"(?m)path\s*\(\s*['\"]([^'\"]+)['\"]")),
    ("py", "django-url", re.compile(r"(?m)url\s*\(\s*r?['\"]([^'\"]+)['\"]")),
    ("js", "next-route", re.compile(r"(?m)(?:export\s+(?:async\s+)?function|const)\s+(GET|POST|PUT|PATCH|DELETE)\s*\(")),
    ("java", "spring", re.compile(r"(?m)@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*['\"]([^'\"]+)['\"]")),
    ("php", "laravel", re.compile(r"(?m)Route::(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]")),
    ("rb", "rails", re.compile(r"(?m)\b(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]")),
    ("go", "gin", re.compile(r"(?m)\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*['\"]([^'\"]+)['\"]")),
]


def discover_routes(root: Path) -> list[dict[str, Any]]:
    """Find candidate routes in source files. Deterministic, no execution."""
    routes: dict[str, dict[str, Any]] = {}
    try:
        files = [p for p in root.rglob("*") if _safe_is_file(p) and p.suffix in (".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".php", ".rb", ".go")]
    except OSError:
        return []
    for path in files:
        rel = str(path.relative_to(root))
        if any(part in {"node_modules", ".git", "__pycache__"} for part in path.parts):
            continue
        try:
            if path.stat().st_size > 512 * 1024:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lang, fw, pattern in ROUTE_PATTERNS:
            for m in pattern.finditer(text):
                if fw in ("express", "express-var") and m.lastindex == 2:
                    route, methods = m.group(2), m.group(1)
                elif fw == "flask" and m.lastindex == 2:
                    route, methods = m.group(1), m.group(2) or "GET"
                elif fw == "fastapi":
                    route = m.group(1)
                    methods = m.group(0).split(".")[-1].split("(")[0].upper()
                elif fw in ("django", "django-url", "spring", "laravel"):
                    route, methods = m.group(1), "GET,POST"
                elif fw == "rails":
                    route, methods = m.group(2), m.group(1).upper()
                elif fw == "gin":
                    route, methods = m.group(2), m.group(1)
                elif fw == "next-route":
                    route, methods = "/", m.group(1)
                else:
                    continue
                route = route.replace("<int:", "{").replace("<string:", "{").replace("<", "{").replace(">", "}")
                route = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "{id}", route)
                # strip query-ish and file extensions
                route = route.split("?")[0]
                if not route.startswith("/"):
                    route = "/" + route
                if route in ("//", "/favicon.ico", "/robots.txt"):
                    continue
                line = text[:m.start()].count("\n") + 1
                # Capture surrounding context for source-analysis-based detection
                ctx_start = max(0, m.start() - 300)
                ctx_end = min(len(text), m.end() + 300)
                source_snippet = text[ctx_start:ctx_end]
                key = f"{route}|{methods}"
                if key not in routes:
                    routes[key] = {
                        "path": route,
                        "methods": methods,
                        "source_file": rel,
                        "line": line,
                        "auth_hint": bool(re.search(r"(?i)(auth|login|token|session|permission|require)", text[max(0, m.start() - 200):m.end() + 200])),
                        "source_snippet": source_snippet,
                    }
    return sorted(routes.values(), key=lambda r: r["path"])
