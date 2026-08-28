"""Bandit adapter - Python SAST (supplements Semgrep for Python projects).

Runs Bandit over the working copy when the project contains Python sources.
Output is parsed from JSON into normalized findings. Skips gracefully when
Bandit is missing or the project has no Python code.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from events import log
from services.scan_context import ScanContext
from tools.base import ToolAdapter, clamp_confidence, make_finding, normalize_severity
from utils.process import ProcessSpec, run_process

_CONFIDENCE = {"LOW": 0.4, "MEDIUM": 0.7, "HIGH": 0.9}


class BanditAdapter(ToolAdapter):
    name = "bandit"
    display_name = "Bandit (Python SAST)"

    def detect(self) -> bool:
        return shutil.which("bandit") is not None

    def version(self) -> str | None:
        res = run_process(ProcessSpec(cmd=["bandit", "--version"], timeout_s=30))
        if res.exit_code == 0:
            line = (res.stdout or res.stderr).splitlines()[0]
            return line.split("[")[0].strip() or line
        return None

    def install_hint(self) -> str:
        return "pip install bandit"

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        py_files = list(ctx.working.rglob("*.py"))
        if not py_files:
            return []
        out_path = ctx.workspace / "artifacts" / "bandit.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        res = run_process(ProcessSpec(
            cmd=["bandit", "-r", str(ctx.working), "-f", "json", "-o", str(out_path), "-q", "-n", "5"],
            timeout_s=600,
            cwd=str(ctx.workspace),
        ))
        if res.timed_out:
            ctx.add_limitation("Bandit timed out - Python SAST incomplete")
            return []
        if res.exit_code not in (0, 1):  # 1 = findings found
            log(ctx.scan_id, f"bandit exited {res.exit_code}: {(res.stderr or res.stdout)[-300:]}")
            ctx.add_limitation("Bandit failed to run")
            return []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            ctx.add_limitation("Bandit produced no parseable output")
            return []

        findings: list[dict[str, Any]] = []
        for item in data.get("results", []):
            rel = item.get("filename", "")
            try:
                rel = str(Path(rel).resolve().relative_to(ctx.working.resolve()))
            except ValueError:
                pass
            severity = normalize_severity(item.get("issue_severity", "MEDIUM"))
            findings.append(make_finding(
                title=f"Bandit: {item.get('test_name', 'issue')}",
                category=_categorize(item.get("test_id", "")),
                severity=severity,
                confidence=clamp_confidence(_CONFIDENCE.get(item.get("issue_confidence", "MEDIUM"), 0.6)),
                source="bandit",
                affected_component=rel,
                affected_file=rel,
                line_start=item.get("line_number"),
                line_end=item.get("end_line"),
                description=(item.get("issue_text") or "") + (("\n\nCode:\n```\n" + item.get("code", "")[:1500] + "\n```") if item.get("code") else ""),
                why_it_matters="Known-unsafe Python patterns are a common source of exploitable bugs.",
                evidence={"tool": "bandit", "test_id": item.get("test_id"), "severity": item.get("issue_severity"), "confidence": item.get("issue_confidence"), "more_info": item.get("more_info")},
                reproduction={"steps": [f"Review {rel}:{item.get('line_number')}"], "tool": "bandit"},
                provenance="Confirmed",
            ))
        return findings


def _categorize(test_id: str) -> str:
    tid = (test_id or "").upper()
    if any(k in tid for k in ("B602", "B603", "B604", "B605", "B606", "B607", "B624", "B611")):
        return "injection"
    if any(k in tid for k in ("B701", "B702", "B703", "B704")):
        return "xss"
    if any(k in tid for k in ("B108", "B112")):
        return "file_security"
    if any(k in tid for k in ("B105", "B106", "B107")):
        return "secrets"
    if any(k in tid for k in ("B201", "B202", "B210", "B212")):
        return "authentication"
    if any(k in tid for k in ("B307", "B308", "B310", "B322", "B323", "B324")):
        return "injection"
    return "code_quality"
