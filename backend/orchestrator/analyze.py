"""AI analysis phase - root-cause tracing for high-value findings."""
from __future__ import annotations

import time as _time

from events import log
from services.scan_context import ScanContext

MAX_ANALYZED = 4
MIN_SEVERITY_RANK = 1  # HIGH and above (CRITICAL=3, HIGH=2)


def run_root_cause_analysis(ctx: ScanContext, deadline: float = 0) -> None:
    from agents.root_cause_agent import run_root_cause_agent
    from tools.base import SEVERITY_RANK

    findings = [f for f in ctx.findings_bank if f.get("severity") in ("CRITICAL", "HIGH")][:MAX_ANALYZED]
    if not findings:
        findings = sorted(ctx.findings_bank, key=lambda f: -f.get("confidence", 0))[:3]
    for finding in findings:
        if ctx.cancel_event.is_set():
            return
        if deadline and _time.time() >= deadline:
            log(ctx.scan_id, "Root-cause analysis time budget exhausted")
            return
        if not finding.get("affected_file") and not (finding.get("evidence") or {}).get("target"):
            continue
        run_root_cause_agent(ctx, finding)
        _time.sleep(1.5)  # pace AI calls to respect provider rate limits
