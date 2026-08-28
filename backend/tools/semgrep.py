"""Semgrep adapter - SAST over the project's working copy.

Runs an offline conservative rule set. Structured JSON output is parsed
into normalized findings. Skips gracefully when semgrep is missing.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from events import log
from services.scan_context import ScanContext
from tools.base import ToolAdapter, clamp_confidence, make_finding, normalize_severity
from utils.process import ProcessSpec, run_process

RULES_FILE = Path(__file__).parent / "rules" / "semgrep-rules.yml"


class SemgrepAdapter(ToolAdapter):
    name = "semgrep"
    display_name = "Semgrep"

    def detect(self) -> bool:
        return shutil.which("semgrep") is not None

    def version(self) -> str | None:
        res = run_process(ProcessSpec(cmd=["semgrep", "--version"], timeout_s=30))
        return res.stdout.strip() if res.exit_code == 0 else None

    def install_hint(self) -> str:
        return "pip install semgrep   (or: pipx install semgrep)"

    def fallback(self, ctx: ScanContext) -> list[dict[str, Any]]:
        """Deterministic built-in analyzer when Semgrep is unavailable."""
        from services.probes.static import scan_static

        ctx.add_limitation("Semgrep unavailable - used built-in static analyzer (real pattern matches, labeled static-fallback)")
        return scan_static(ctx.working)

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        target = ctx.working
        if not RULES_FILE.exists():
            ctx.add_limitation("semgrep rules file missing")
            return []
        out_path = ctx.workspace / "artifacts" / "semgrep.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        res = run_process(ProcessSpec(
            cmd=[
                "semgrep", "--config", str(RULES_FILE), "--json", "-o", str(out_path),
                "--no-rewrite-rule-ids", "--quiet",
                str(target),
            ],
            timeout_s=600,
            cwd=str(ctx.workspace),
        ))
        if res.exit_code not in (0, 1):  # 1 = findings found; anything else = failure
            log(ctx.scan_id, f"semgrep exited {res.exit_code}: {res.stderr[-400:]}")
            return []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return []
        findings = []
        for result in data.get("results", []):
            rel = result.get("path", "")
            try:
                rel = str(Path(rel).resolve().relative_to(ctx.working.resolve()))
            except ValueError:
                pass
            extra = result.get("extra", {})
            lines = extra.get("lines", "")
            finding = make_finding(
                title=extra.get("message", "").split("\n")[0][:200] or "SAST finding",
                category=_categorize(result.get("check_id", "")),
                severity=normalize_severity(extra.get("severity", "MEDIUM")),
                confidence=0.7,
                source="semgrep",
                affected_component=rel,
                affected_file=rel,
                line_start=result.get("start", {}).get("line"),
                line_end=result.get("end", {}).get("line"),
                description=extra.get("message", "") + ("\n\nCode:\n```\n" + lines[:2000] + "\n```" if lines else ""),
                evidence={
                    "tool": "semgrep",
                    "rule": result.get("check_id"),
                    "severity": extra.get("severity"),
                    "code_snippet": lines[:2000],
                    "metadata": extra.get("metadata", {}),
                },
                reproduction={"steps": [f"Review {rel}:{result.get('start', {}).get('line')}"], "tool": "semgrep"},
            )
            findings.append(finding)
        return findings


def _categorize(check_id: str) -> str:
    cid = check_id.lower()
    if "sqli" in cid or "injection" in cid or "eval" in cid or "template" in cid:
        return "injection"
    if "xss" in cid:
        return "xss"
    if "path" in cid:
        return "file_security"
    if "secret" in cid or "hardcoded" in cid:
        return "secrets"
    if "cors" in cid or "cookie" in cid:
        return "configuration"
    if "debug" in cid:
        return "configuration"
    return "code_quality"
