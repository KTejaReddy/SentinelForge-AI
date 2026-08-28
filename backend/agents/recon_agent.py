"""Recon Agent - enriches deterministic fingerprinting with an AI-built
application map (components, attack surface, auth notes, data flows)."""
from __future__ import annotations

from typing import Any

from agents.base import record_agent, run_structured_agent
from events import agent_event, log
from services.ai.context import build_project_context
from services.scan_context import ScanContext


def run_recon_agent(ctx: ScanContext) -> dict[str, Any]:
    agent_event(ctx.scan_id, "recon_agent", "RUNNING")
    user = build_project_context(ctx, max_files=10) + "\n\nBuild the application map as JSON."
    data, error = run_structured_agent(ctx, "recon_agent", user, max_tokens=1800)
    if error:
        ctx.add_limitation(f"Recon Agent: {error}")
        record_agent(ctx.scan_id, "recon_agent", "SKIPPED", error)
        return {"summary": "", "components": [], "attack_surface": [], "auth_notes": "", "data_flows": []}
    record_agent(ctx.scan_id, "recon_agent", "DONE", data.get("summary", ""))
    ctx.detection["ai_map"] = data
    log(ctx.scan_id, "Recon Agent: application map built")
    return data
