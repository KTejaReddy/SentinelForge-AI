"""Nuclei adapter - template-based web/API checks.

Targets are restricted to the sandboxed application's loopback endpoint;
the exact template IDs that ran are recorded in the report.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding, normalize_severity
from utils.process import ProcessSpec, run_process


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    display_name = "Nuclei"

    def detect(self) -> bool:
        return shutil.which("nuclei") is not None

    def version(self) -> str | None:
        res = run_process(ProcessSpec(cmd=["nuclei", "-version"], timeout_s=30))
        return (res.stdout or "").splitlines()[0] if res.exit_code == 0 else None

    def install_hint(self) -> str:
        return "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  |  https://docs.projectdiscovery.io"

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        base_url = ctx.runtime.get("base_url")
        if not base_url:
            ctx.add_limitation("Nuclei skipped: application did not start")
            return []
        out_path = ctx.workspace / "artifacts" / "nuclei.jsonl"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        res = run_process(ProcessSpec(
            cmd=[
                "nuclei", "-u", base_url, "-jsonl", "-o", str(out_path),
                "-timeout", "5", "-rl", "20", "-c", "5",
                "-duc", "-nc", "-silent", "-retries", "1",
            ],
            timeout_s=600,
            cwd=str(ctx.workspace),
        ))
        findings: list[dict[str, Any]] = []
        if not out_path.exists():
            ctx.add_limitation("Nuclei produced no output (templates may need `nuclei -update-templates`)")
            return findings
        template_ids: set[str] = set()
        for line in out_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            template_ids.add(item.get("template-id", ""))
            findings.append(make_finding(
                title=f"Nuclei: {item.get('info', {}).get('name', item.get('template-id'))}",
                category=_cat(item.get("info", {}).get("tags", "")),
                severity=normalize_severity(item.get("info", {}).get("severity", "MEDIUM")),
                confidence=0.75,
                source="nuclei",
                affected_component=item.get("matched-at", base_url),
                description=(item.get("info", {}).get("description") or item.get("matched-at") or "")[:600],
                evidence={"tool": "nuclei", "template_id": item.get("template-id"), "matched_at": item.get("matched-at"), "matcher": item.get("matcher-name"), "extracted": (item.get("extracted-results") or [])[:3]},
                reproduction={"steps": [f"nuclei -u {base_url} -t {item.get('template-id')}"], "tool": "nuclei"},
            ))
        if template_ids:
            ctx.tool_results["nuclei"] = {"template_ids": sorted(template_ids)}
        return findings


def _cat(tags: str) -> str:
    t = tags.lower()
    if "xss" in t:
        return "xss"
    if "sqli" in t:
        return "injection"
    if "cve" in t or "vulnerability" in t:
        return "dependencies"
    if "auth" in t or "login" in t:
        return "authentication"
    if "exposure" in t or "config" in t or "misconfig" in t:
        return "configuration"
    return "web_security"
