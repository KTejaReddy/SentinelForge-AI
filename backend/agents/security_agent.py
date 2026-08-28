"""Red-Team Security Agent - correlates raw findings, refines severity and
confidence, identifies likely attack paths, and generates follow-up test
ideas. Never claims an attack without evidence."""
from __future__ import annotations

from typing import Any

from agents.base import record_agent, run_structured_agent
from events import agent_event, log
from services.ai.context import summarize_findings
from services.scan_context import ScanContext


def run_security_agent(ctx: ScanContext, findings: list[dict[str, Any]]) -> dict[str, Any]:
    agent_event(ctx.scan_id, "security_agent", "RUNNING")
    if not findings:
        record_agent(ctx.scan_id, "security_agent", "DONE", "no findings to correlate")
        return {}
    user = (
        "Current normalized findings:\n" + summarize_findings(findings, limit=40) +
        "\n\nCorrelate and prioritize as JSON."
    )
    data, error = run_structured_agent(ctx, "security_agent", user, max_tokens=2500)
    if error:
        ctx.add_limitation(f"Security Agent: {error}")
        record_agent(ctx.scan_id, "security_agent", "SKIPPED", error)
        return {}
    assessments = data.get("assessments", []) or []
    # Apply AI refinements back onto findings (severity/confidence), only
    # where the AI provides concrete evidence-based reasoning.
    for assessment in assessments:
        title = (assessment.get("finding") or "").lower()
        for f in findings:
            if title and title in f.get("title", "").lower():
                if assessment.get("severity"):
                    f["severity"] = assessment["severity"].upper()
                if isinstance(assessment.get("confidence"), (int, float)):
                    f["confidence"] = max(0.0, min(1.0, float(assessment["confidence"])))
                f["ai_explanation"] = _explanation(assessment)
                break
    log(ctx.scan_id, f"Security Agent: correlated {len(findings)} findings")
    record_agent(ctx.scan_id, "security_agent", "DONE", f"correlated {len(findings)} findings")
    return data


def _explanation(a: dict[str, Any]) -> str:
    parts = []
    for key, label in (("observation", "Observation"), ("evidence", "Evidence"), ("likely_root_cause", "Likely root cause"), ("recommended_action", "Recommended action")):
        if a.get(key):
            parts.append(f"{label}: {a[key]}")
    return "\n".join(parts)
