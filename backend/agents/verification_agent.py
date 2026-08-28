"""Verification Agent - compares before/after reproduction evidence and
decides FIXED / PARTIALLY_FIXED / NOT_FIXED / NEEDS_HUMAN_REVIEW."""
from __future__ import annotations

from typing import Any

from agents.base import AGENT_PROMPTS, record_agent, run_structured_agent
from events import agent_event, log
from services.scan_context import ScanContext

VALID = ("FIXED", "PARTIALLY_FIXED", "NOT_FIXED", "NEEDS_HUMAN_REVIEW")


def decide_verification(ctx: ScanContext, finding: dict[str, Any], before: dict[str, Any], after: dict[str, Any], build_pass: bool, regression_pass: bool) -> dict[str, Any]:
    """Deterministic decision first; AI narrative when available."""
    exploit_blocked = _exploit_blocked(before, after)
    if build_pass and exploit_blocked and regression_pass:
        status = "FIXED"
    elif build_pass and exploit_blocked:
        status = "PARTIALLY_FIXED"
    elif not build_pass:
        status = "NEEDS_HUMAN_REVIEW"
    else:
        status = "NOT_FIXED"

    agent_event(ctx.scan_id, "verification_agent", "RUNNING", finding.get("title", ""))
    user = (
        f"Finding: {finding.get('title')}\n"
        f"Before patch reproduction: {before}\n"
        f"After patch reproduction: {after}\n"
        f"Build after patch: {'PASS' if build_pass else 'FAIL'}\n"
        f"Regression tests: {'PASS' if regression_pass else 'FAIL'}\n"
        "Decide the status as JSON."
    )
    data, error = run_structured_agent(ctx, "verification_agent", user, max_tokens=900)
    if not error and data.get("status") in VALID:
        status = data["status"]
    result = {
        "status": status,
        "build_pass": bool(build_pass),
        "regression_pass": bool(regression_pass),
        "exploit_blocked": bool(exploit_blocked),
        "reason": data.get("reason", "") if data else "",
        "ai_evidence": data.get("evidence", "") if data else "",
    }
    record_agent(ctx.scan_id, "verification_agent", "DONE", status)
    log(ctx.scan_id, f"Verification: {status} - {finding.get('title')}")
    return result


def _exploit_blocked(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Compare reproduction outcomes: the exploit worked before, not after."""
    b = before.get("exploited")
    a = after.get("exploited")
    if b is None or a is None:
        # Fall back to status-code comparison when available.
        bs = before.get("status_code")
        as_ = after.get("status_code")
        if bs and as_ and bs == 200 and as_ != 200:
            return True
        return False
    return bool(b) and not bool(a)
