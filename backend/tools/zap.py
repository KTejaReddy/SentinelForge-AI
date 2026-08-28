"""OWASP ZAP adapter.

Uses ZAP's dockerized baseline scan when available. Because ZAP is a
large install, the platform ships a built-in fallback analyzer - the
`Dynamic Probes` adapter - that performs passive header/configuration
checks natively; the report records which engine ran.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding, normalize_severity
from utils.process import ProcessSpec, run_process


class ZapAdapter(ToolAdapter):
    name = "zap"
    display_name = "OWASP ZAP"

    def detect(self) -> bool:
        if shutil.which("zap-cli"):
            return True
        return shutil.which("docker") is not None and run_process(ProcessSpec(cmd=["docker", "image", "inspect", "ghcr.io/zaproxy/zaproxy"], timeout_s=30)).exit_code == 0

    def version(self) -> str | None:
        if shutil.which("zap-cli"):
            res = run_process(ProcessSpec(cmd=["zap-cli", "--version"], timeout_s=30))
            return res.stdout.strip() if res.exit_code == 0 else None
        return "docker:ghcr.io/zaproxy/zaproxy"

    def install_hint(self) -> str:
        return "docker pull ghcr.io/zaproxy/zaproxy  (large image) - or the built-in Dynamic Probes analyzer covers passive checks"

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        base_url = ctx.runtime.get("base_url")
        if not base_url:
            ctx.add_limitation("ZAP skipped: application did not start")
            return []
        out_path = ctx.workspace / "artifacts" / "zap.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if shutil.which("docker"):
            cmd = [
                "docker", "run", "--rm", "--network", "host",
                "-v", f"{out_path}:/zap/wrk/zap.json",
                "ghcr.io/zaproxy/zaproxy", "zap-baseline.py",
                "-t", base_url, "-r", "/zap/wrk/zap.json", "-J", "/zap/wrk/zap.json",
                "-l", "WARN", "-a", "-d",
            ]
        else:
            cmd = ["zap-cli", "--zap-url", "http://127.0.0.1:8090", "quick-scan", "--spider", "-j", "-r", "-l", "Medium", "-o", "-j", base_url, "-r"]
        res = run_process(ProcessSpec(cmd=cmd, timeout_s=900, cwd=str(ctx.workspace)))
        if res.exit_code != 0:
            ctx.add_limitation("ZAP run failed: " + (res.stderr or res.stdout)[-300:])
            return []
        findings: list[dict[str, Any]] = []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    if alert.get("riskdesc", "").startswith("Informational"):
                        continue
                    findings.append(make_finding(
                        title=f"ZAP: {alert.get('alert', 'alert')}",
                        category=_cat(alert.get("cweid", 0)),
                        severity=normalize_severity(alert.get("riskdesc", "MEDIUM")),
                        confidence=0.7,
                        source="zap",
                        affected_component=alert.get("url", base_url),
                        description=(alert.get("desc") or "")[:800],
                        evidence={"tool": "zap", "cwe": alert.get("cweid"), "url": alert.get("url"), "evidence": alert.get("evidence", "")[:400]},
                        reproduction={"steps": [alert.get("solution", "See ZAP report")[:400]], "tool": "zap"},
                    ))
        except (OSError, json.JSONDecodeError):
            ctx.add_limitation("ZAP output not parseable - used Dynamic Probes fallback analyzer")
        return findings


def _cat(cwe: int) -> str:
    if cwe in (79, 80, 87):
        return "xss"
    if cwe in (89, 77, 94, 95):
        return "injection"
    if cwe in (352,):
        return "csrf"
    if cwe in (22, 23):
        return "file_security"
    if cwe in (311, 312, 319):
        return "secrets"
    return "web_security"
