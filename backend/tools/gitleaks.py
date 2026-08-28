"""Gitleaks adapter - scans the working copy for committed secrets.

When Gitleaks is not installed, the deterministic built-in regex scanner
(services.probes.secrets) is used instead; the report records which
engine actually ran.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from services.probes.secrets import scan_secrets
from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding
from utils.process import ProcessSpec, run_process


class GitleaksAdapter(ToolAdapter):
    name = "gitleaks"
    display_name = "Gitleaks"

    def detect(self) -> bool:
        return shutil.which("gitleaks") is not None

    def version(self) -> str | None:
        res = run_process(ProcessSpec(cmd=["gitleaks", "version"], timeout_s=30))
        return res.stdout.strip() if res.exit_code == 0 else None

    def install_hint(self) -> str:
        return "brew install gitleaks  |  https://github.com/gitleaks/gitleaks/releases"

    def fallback(self, ctx: ScanContext) -> list[dict[str, Any]]:
        """Deterministic built-in regex secret scanner."""
        ctx.add_limitation("Gitleaks unavailable - used built-in regex secret scanner")
        findings = scan_secrets(ctx.working)
        for f in findings:
            f["source"] = "secret-scanner"
        return findings

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        out_path = ctx.workspace / "artifacts" / "gitleaks.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        res = run_process(ProcessSpec(
            cmd=["gitleaks", "detect", "--source", str(ctx.working), "--report-format", "json", "--report-path", str(out_path), "--no-banner", "--exit-code", "0"],
            timeout_s=600,
            cwd=str(ctx.workspace),
        ))
        findings: list[dict[str, Any]] = []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
            for item in data if isinstance(data, list) else []:
                rel = item.get("File", "")
                findings.append(make_finding(
                    title=f"Secret: {item.get('RuleID', 'leak')}",
                    category="secrets",
                    severity="HIGH",
                    confidence=0.9,
                    source="gitleaks",
                    affected_component=rel,
                    affected_file=rel,
                    line_start=item.get("StartLine"),
                    line_end=item.get("EndLine"),
                    description=f"Gitleaks rule `{item.get('RuleID')}` matched in {rel}:{item.get('StartLine')}.",
                    evidence={"tool": "gitleaks", "rule": item.get("RuleID"), "secret": item.get("Secret", "")[:20] + "…", "commit": item.get("Commit")},
                    reproduction={"steps": [f"Review {rel}:{item.get('StartLine')}"], "tool": "gitleaks"},
                ))
        except (OSError, json.JSONDecodeError):
            pass
        if not findings:
            # Fallback: deterministic built-in scanner (real results, not simulated).
            ctx.add_limitation("Gitleaks unavailable or produced no output - used built-in regex secret scanner")
            findings = scan_secrets(ctx.working)
            for f in findings:
                f["source"] = "secret-scanner"
        return findings
