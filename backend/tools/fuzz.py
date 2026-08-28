"""Fuzzing adapter - bounded malformed-input testing of API endpoints.

Bounded: small fixed corpus, per-request timeouts, low request budget,
loopback only. Detects unhandled exceptions (500s) and validation gaps.
"""
from __future__ import annotations

import json
import time
from typing import Any

from events import log
from services.probes.http import probe
from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding

FUZZ_JSON_BODIES = [
    '{"id": "1 OR 1=1"}',
    '{"id": 1, "qty": -1}',
    '{"id": 1, "qty": 999999999}',
    '{"id": [1,2,3]}',
    '{"id": {"$gt": ""}}',
    '{"name": "a' * 200 + '"}',
    '{"role": "admin"}',
    '{"price": 0}',
    '{"id": null}',
    '{"password": ""}',
]
MAX_FUZZ_REQUESTS = 80


class FuzzAdapter(ToolAdapter):
    name = "fuzz"
    display_name = "Fuzzing"

    def detect(self) -> bool:
        return True

    def install_hint(self) -> str:
        return ""

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        base_url = ctx.runtime.get("base_url")
        if not base_url:
            return []
        routes = (ctx.route_map or {}).get("routes", [])
        writable = [r for r in routes if any(m in str(r.get("methods", "")).upper() for m in ("POST", "PUT", "PATCH"))][:8]
        if not writable:
            ctx.tool_results["fuzz"] = {"status": "no writable endpoints"}
            return []
        findings: list[dict[str, Any]] = []
        budget = MAX_FUZZ_REQUESTS
        for route in writable:
            path = route["path"]
            if "{" in path:
                path = re_sub(path)
            url = base_url.rstrip("/") + path
            method = "POST"
            try:
                baseline = probe(method, url, timeout_s=5, json={})
                baseline_status = baseline.status_code
            except Exception:
                continue
            for body in FUZZ_JSON_BODIES:
                if budget <= 0:
                    break
                budget -= 1
                try:
                    resp = probe(method, url, timeout_s=5, content=body, headers={"Content-Type": "application/json"})
                    if resp.status_code == 500:
                        findings.append(make_finding(
                            title="Fuzzing: unhandled exception on malformed JSON body",
                            category="reliability", severity="MEDIUM", confidence=0.7, source="fuzz",
                            affected_component=path,
                            affected_file=route.get("source_file", ""),
                            line_start=route.get("line"),
                            description=f"POST {path} returns HTTP 500 for body: {body[:120]}. Baseline status: {baseline_status}.",
                            evidence={"tool": "fuzz", "target": url, "request": f"POST {path}\n{body[:300]}", "response": request_summary(resp)},
                            reproduction={"method": "POST", "path": path, "body": body, "expect": {"status": 500}, "steps": [f"POST {path} with {body[:80]}"], "tool": "fuzz"},
                        ))
                        break
                    time.sleep(0.02)
                except Exception:
                    continue
            if budget <= 0:
                break
        ctx.tool_results["fuzz"] = {"requests": MAX_FUZZ_REQUESTS - budget, "findings": len(findings)}
        if findings:
            log(ctx.scan_id, f"Fuzzing: {len(findings)} issue(s) found")
        return findings


def request_summary(resp: Any) -> dict[str, Any]:
    return {"status": resp.status_code, "headers": {k: v for k, v in resp.headers.items()}, "body_preview": (resp.text or "")[:1200]}


def re_sub(path: str) -> str:
    import re

    return re.sub(r"\{[^}]+\}", "1", path)
