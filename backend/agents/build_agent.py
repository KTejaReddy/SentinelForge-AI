"""Build Agent - interprets build/runtime failures, proposes minimal safe
fixes to the working copy, and triggers retries (bounded)."""
from __future__ import annotations

from typing import Any

from agents.base import AGENT_PROMPTS, record_agent, run_structured_agent
from events import agent_event, log
from services.ai.groq_client import parse_json_content
from services.patching.patch_engine import apply_patch, validate_patch
from services.scan_context import ScanContext


def attempt_build_fix(ctx: ScanContext, build_log: str) -> bool:
    """Try one AI-guided repair of the build. Returns True if a fix was applied."""
    if not build_log.strip():
        return False
    agent_event(ctx.scan_id, "build_agent", "RUNNING")
    user = (
        "Build/runtime log (tail):\n```\n" + build_log[-6000:] + "\n```\n"
        "Diagnose and propose minimal fixes as JSON."
    )
    data, error = run_structured_agent(ctx, "build_agent", user, max_tokens=1800)
    if error:
        ctx.add_limitation(f"Build Agent: {error}")
        record_agent(ctx.scan_id, "build_agent", "SKIPPED", error)
        return False
    if isinstance(data, str):
        parsed = parse_json_content(data) or {}
    else:
        parsed = data
    fixes = parsed.get("fixes") or []
    if not fixes:
        record_agent(ctx.scan_id, "build_agent", "DONE", "no safe fix proposed")
        return False
    patch = {"files": {}}
    for fix in fixes[:3]:
        fpath = (fix.get("file") or "").lstrip("/")
        old, new = fix.get("replace", {}).get("old"), fix.get("replace", {}).get("new")
        if fpath and old and new:
            patch["files"][fpath] = {"old": old, "new": new}
    if not patch["files"]:
        record_agent(ctx.scan_id, "build_agent", "DONE", "no usable fix")
        return False
    errors = validate_patch(patch, ctx)
    if errors:
        ctx.add_limitation(f"Build Agent fix rejected: {'; '.join(errors)[:300]}")
        record_agent(ctx.scan_id, "build_agent", "FAILED", "; ".join(errors)[:500])
        return False
    ok, _, _ = apply_patch(patch, ctx)
    if ok:
        record_agent(ctx.scan_id, "build_agent", "DONE", parsed.get("diagnosis", "")[:800])
        log(ctx.scan_id, "Build Agent: applied fix, retrying build")
        return True
    return False
