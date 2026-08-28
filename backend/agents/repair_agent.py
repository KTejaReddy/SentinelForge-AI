"""Repair Agent - generates the minimal patch that fixes the root cause.

Output is validated by the patch engine (snippet must exist verbatim,
path must stay inside the working copy) before anything is written.
"""
from __future__ import annotations

from typing import Any

from agents.base import AGENT_PROMPTS, agent_loop, record_agent
from events import agent_event, log
from services.ai.groq_client import parse_json_content
from services.scan_context import ScanContext


def run_repair_agent(ctx: ScanContext, finding: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    agent_event(ctx.scan_id, "repair_agent", "RUNNING", finding.get("title", ""))
    user = _user_prompt(ctx, finding)
    raw, error = agent_loop(ctx, AGENT_PROMPTS["repair_agent"], user, max_rounds=4)
    if error:
        ctx.add_limitation(f"Repair Agent: {error}")
        record_agent(ctx.scan_id, "repair_agent", "SKIPPED", error)
        return None, error
    if isinstance(raw, str):
        patch = parse_json_content(raw) or {}
    else:
        patch = {}
    if not patch.get("files"):
        record_agent(ctx.scan_id, "repair_agent", "FAILED", "no patch produced")
        return None, "repair agent produced no patch"
    record_agent(ctx.scan_id, "repair_agent", "DONE", patch.get("explanation", "")[:1000])
    return patch, ""


def _user_prompt(ctx: ScanContext, finding: dict[str, Any]) -> str:
    lines = [
        "## Finding",
        f"- title: {finding.get('title')}",
        f"- category: {finding.get('category')}",
        f"- root cause: {finding.get('root_cause', '')[:1200]}",
        f"- recommended fix (from root cause analysis): {finding.get('recommended_fix', '')[:1200]}",
        f"- affected file: {finding.get('affected_file')}",
        "",
        "## Current file content",
    ]
    if finding.get("affected_file"):
        cand = ctx.working / finding["affected_file"]
        if cand.exists():
            try:
                lines.append(f"```\n{cand.read_text(encoding='utf-8', errors='replace')[:10_000]}\n```")
            except OSError:
                pass
    else:
        # no file hint: let the agent pick from the tree via tools
        pass
    lines.append("")
    lines.append(
        "Generate the minimal patch. The 'old' snippets must match the current file verbatim. "
        "If a regression test is practical, include it in 'regression_test' (file + content)."
    )
    return "\n".join(lines)
