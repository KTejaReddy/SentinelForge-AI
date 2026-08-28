"""Root Cause Agent - traces a finding to its source, using the safe tool
loop to inspect code, search symbols, and check runtime evidence."""
from __future__ import annotations

from typing import Any

from agents.base import AGENT_PROMPTS, agent_loop, record_agent
from events import agent_event, log
from services.ai.groq_client import parse_json_content
from services.scan_context import ScanContext


def run_root_cause_agent(ctx: ScanContext, finding: dict[str, Any]) -> dict[str, Any]:
    agent_event(ctx.scan_id, "root_cause_agent", "RUNNING", finding.get("title", ""))
    user = _user_prompt(ctx, finding)
    raw, error = agent_loop(ctx, AGENT_PROMPTS["root_cause_agent"], user, max_rounds=5)
    if error:
        ctx.add_limitation(f"Root Cause Agent: {error}")
        record_agent(ctx.scan_id, "root_cause_agent", "SKIPPED", error)
        return {}
    if isinstance(raw, str):
        data = parse_json_content(raw) or {}
    else:
        data = {}
    if not data:
        record_agent(ctx.scan_id, "root_cause_agent", "FAILED", "unparseable output")
        return {}
    finding["root_cause"] = data.get("root_cause", "")
    finding["affected_file"] = data.get("affected_file") or finding.get("affected_file", "")
    finding["line_start"] = data.get("line_start") or finding.get("line_start")
    finding["line_end"] = data.get("line_end") or finding.get("line_end")
    finding["recommended_fix"] = data.get("recommended_fix", "")
    finding["why_it_matters"] = data.get("why_it_matters", "") or finding.get("why_it_matters", "")
    finding["ai_explanation"] = _explanation(data)
    finding["confidence"] = max(finding.get("confidence", 0.5), float(data.get("confidence") or 0.5))
    record_agent(ctx.scan_id, "root_cause_agent", "DONE", finding.get("root_cause", ""))
    log(ctx.scan_id, f"Root cause identified for: {finding.get('title')}")
    return data


def _user_prompt(ctx: ScanContext, finding: dict[str, Any]) -> str:
    lines = [
        "## Finding",
        f"- title: {finding.get('title')}",
        f"- category: {finding.get('category')}",
        f"- severity: {finding.get('severity')}",
        f"- source: {finding.get('source')}",
        f"- affected file (hint): {finding.get('affected_file')}",
        f"- line hint: {finding.get('line_start')}",
        f"- description: {finding.get('description', '')[:1500]}",
        f"- evidence: {str(finding.get('evidence'))[:2000]}",
        f"- reproduction: {str(finding.get('reproduction'))[:1200]}",
        "",
        "## Relevant code",
    ]
    if finding.get("affected_file"):
        cand = ctx.working / finding["affected_file"]
        if cand.exists():
            try:
                lines.append(f"```\n{cand.read_text(encoding='utf-8', errors='replace')[:6000]}\n```")
            except OSError:
                pass
    lines.append("")
    lines.append("Trace the root cause to the exact source location. Output the required JSON.")
    return "\n".join(lines)


def _explanation(d: dict[str, Any]) -> str:
    parts = []
    if d.get("data_flow"):
        parts.append("Data flow:\n- " + "\n- ".join(d["data_flow"][:8]))
    if d.get("root_cause"):
        parts.append("Root cause: " + d["root_cause"])
    if d.get("recommended_fix"):
        parts.append("Recommended fix: " + d["recommended_fix"])
    return "\n".join(parts)
