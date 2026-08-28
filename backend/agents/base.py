"""Multi-agent framework.

Every agent gets a purpose-built system prompt, relevant context only, and
(where useful) the safe tool loop. Costs and calls are tracked per scan.
No chain-of-thought is ever exposed - agents emit structured reasoning
summaries (Observation / Evidence / Likely root cause / Recommended action).
"""
from __future__ import annotations

import json
import time
from typing import Any

from config import settings
from database import SessionLocal
from events import agent_event, log
from models import AgentRun
from services.ai.groq_client import GroqClient, parse_json_content
from services.ai.tools import TOOL_DEFS, TOOL_FUNCS
from security import redact_text

_last_ai_call_time: float = 0.0
AI_CALL_COOLDOWN: float = 2.0  # seconds between AI calls to avoid rate limits

AGENT_PROMPTS: dict[str, str] = {
    "recon_agent": (
        "You are the Recon Agent of SentinelForge, an autonomous application-security engineer. "
        "Your job: understand the uploaded project's structure, frameworks, components, routes, APIs, forms, "
        "authentication, and data storage. Build an application map. Output JSON: "
        '{"summary": "...", "components": ["..."], "attack_surface": ["..."], "auth_notes": "...", "data_flows": ["..."]}. '
        "Be concise. Only state what the provided context supports. Do not invent vulnerabilities here."
    ),
    "security_agent": (
        "You are the Red-Team Security Agent. Correlate the scanner/probe findings below, prioritize the most likely "
        "real attack paths, and for each priority finding produce a short structured reasoning summary with fields: "
        "finding, severity (CRITICAL/HIGH/MEDIUM/LOW), confidence (0-1), observation, evidence, likely_root_cause, "
        "recommended_action. Output a JSON object with a \"assessments\" array. Never claim an attack succeeded "
        "without evidence. Mark uncertainty explicitly."
    ),
    "api_agent": (
        "You are the API Security Agent. From the discovered routes and probe results, identify API security issues: "
        "missing auth, missing authorization, excessive data exposure, weak input validation, method abuse, debug endpoints. "
        'Output JSON: {"assessments": [{"endpoint": "...", "issue": "...", "severity": "...", "confidence": 0.0, "evidence": "...", "recommended_action": "..."}]}.'
    ),
    "browser_agent": (
        "You are the Browser Agent. From the browser/crawl results (pages visited, forms found, console errors, failed requests), "
        "summarize UI state, broken workflows, and any client-side issues. "
        'Output JSON: {"summary": "...", "ui_issues": [{"issue": "...", "evidence": "...", "severity": "..."}], "workflows": ["..."]}.'
    ),
    "bug_hunter_agent": (
        "You are the Bug Hunter Agent. From runtime logs, dynamic probe results, and test output, find ordinary application bugs: "
        "crashes, unhandled exceptions, broken requests, inconsistent behavior. Output JSON: "
        '{"bugs": [{"title": "...", "evidence": "...", "category": "...", "severity": "...", "confidence": 0.0, "reproduction": "..."}]}.'
    ),
    "dependency_agent": (
        "You are the Dependency Agent. Correlate dependency scanner results: prioritize exploitable, reachable, or known-CVE issues. "
        'Output JSON: {"assessment": [{"package": "...", "issue": "...", "severity": "...", "reachable": "unknown|likely|unlikely", "recommendation": "..."}]}.'
    ),
    "secret_agent": (
        "You are the Secrets Agent. Review the detected secret patterns. Classify each as real leak, likely-test-value, or demo value. "
        "Prioritize real credentials. Output JSON: {\"secrets\": [{\"file\": \"...\", \"type\": \"...\", \"verdict\": \"real|test|demo\", \"action\": \"...\"}]}."
    ),
    "fuzz_agent": (
        "You are the Fuzzing Agent. From the malformed-input probe results, identify endpoints with weak input validation or "
        "unhandled-exception behavior, and propose additional safe targeted tests. Output JSON: "
        '{"observations": [...], "suggested_tests": [{"endpoint": "...", "payloads": ["..."], "why": "..."}]}.'
    ),
    "business_logic_agent": (
        "You are the Business Logic Agent. Analyze the routes, forms, and workflows for logic flaws: workflow bypasses, "
        "state-transition issues, missing validation, trust of client-controlled data, sequence-of-operations problems. "
        "Output JSON: {\"assessments\": [{\"workflow\": \"...\", \"issue\": \"...\", \"severity\": \"...\", \"confidence\": 0.0, \"evidence\": \"...\", \"recommended_action\": \"...\"}]}. "
        "Do not claim a flaw exists without a concrete basis."
    ),
    "build_agent": (
        "You are the Build Agent. Analyze the build/runtime logs below. Identify why the application failed to build or start. "
        "Propose minimal, safe configuration/code fixes (no unrelated changes). Output JSON: "
        '{"diagnosis": "...", "fixes": [{"file": "...", "replace": {"old": "...", "new": "..."}, "reason": "..."}], "confidence": 0.0}.'
    ),
    "root_cause_agent": (
        "You are the Root Cause Agent. Trace the reported finding to its source in the code. Use the provided context and "
        "tools to inspect files, search code, and check runtime evidence. Output JSON: "
        '{"root_cause": "...", "affected_file": "...", "line_start": null, "line_end": null, "confidence": 0.0, '
        '"data_flow": ["..."], "recommended_fix": "...", "why_it_matters": "..."}.'
    ),
    "repair_agent": (
        "You are the Repair Agent. Generate the minimal patch that fixes the root cause. Preserve behavior. "
        "Output JSON: {\"files\": {\"path/to/file\": {\"old\": \"exact snippet\", \"new\": \"replacement\"}}, "
        '"explanation": "...", "regression_test": {"file": "...", "content": "..."} | null}. '
        "The \"old\" snippet must exist verbatim in the current file. Prefer smallest possible change."
    ),
    "verification_agent": (
        "You are the Verification Agent. Compare the reproduction evidence before and after the patch. Decide one status: "
        "FIXED, PARTIALLY_FIXED, NOT_FIXED, or NEEDS_HUMAN_REVIEW. Output JSON: "
        '{"status": "...", "build_pass": true, "regression_pass": true, "exploit_blocked": true, "evidence": "...", "reason": "..."}.'
    ),
}


def record_agent(scan_id: int, agent: str, status: str, summary: str = "", meta: dict[str, Any] | None = None) -> None:
    try:
        db = SessionLocal()
        try:
            run = AgentRun(scan_id=scan_id, agent=agent, status=status, summary=summary[:4000], meta=meta or {})
            db.add(run)
            db.commit()
        finally:
            db.close()
    except Exception:
        pass


def llm(ctx: Any, system: str, user: str, json_mode: bool = False, max_tokens: int | None = None, temperature: float | None = None) -> tuple[Any, str]:
    """One LLM call with budget + availability checks. Returns (parsed_json_or_text, error)."""
    global _last_ai_call_time
    if ctx.ai_calls >= settings.max_ai_calls_per_scan:
        return None, "AI call budget exhausted"
    client = GroqClient()
    if not client.available():
        return None, "Groq unavailable (no API key)"
    # Rate-limit cooldown: wait between calls to avoid 429s
    elapsed = time.time() - _last_ai_call_time
    if elapsed < AI_CALL_COOLDOWN:
        time.sleep(AI_CALL_COOLDOWN - elapsed)
    messages = [
        {"role": "system", "content": redact_text(system)},
        {"role": "user", "content": redact_text(user)[:120_000]},
    ]
    result = client.chat(messages, json_mode=json_mode, max_tokens=max_tokens, temperature=temperature)
    _last_ai_call_time = time.time()
    if not result.ok:
        return None, result.error
    ctx.bump_ai(result.input_tokens, result.output_tokens, result.cost_usd)
    if json_mode:
        parsed = parse_json_content(result.content)
        if parsed is None:
            return None, "malformed AI response (expected JSON)"
        return parsed, ""
    return result.content, ""


def agent_loop(ctx: Any, system: str, user: str, max_rounds: int = 6) -> tuple[Any, str]:
    """Tool-calling loop. Every tool call is executed by the validated
    sandbox-scoped implementations in services/ai/tools.py."""
    global _last_ai_call_time
    if ctx.ai_calls >= settings.max_ai_calls_per_scan:
        return None, "AI call budget exhausted"
    client = GroqClient()
    if not client.available():
        return None, "Groq unavailable (no API key)"
    # Rate-limit cooldown
    elapsed = time.time() - _last_ai_call_time
    if elapsed < AI_CALL_COOLDOWN:
        time.sleep(AI_CALL_COOLDOWN - elapsed)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": redact_text(system)},
        {"role": "user", "content": redact_text(user)[:120_000]},
    ]
    for _ in range(max_rounds):
        result = client.chat(messages, tools=TOOL_DEFS)
        if not result.ok:
            return None, result.error
        ctx.bump_ai(result.input_tokens, result.output_tokens, result.cost_usd)
        if not result.tool_calls:
            if result.content:
                return result.content, ""
            return None, "empty AI response"
        # Some models emit internal/hidden tool calls (e.g. gpt-oss 'commentary')
        # that are NOT in our allowlist. Strip them before echoing the assistant
        # message back, otherwise the API rejects the request.
        allowed_calls = [c for c in result.tool_calls if c.get("function", {}).get("name") in TOOL_FUNCS]
        if not allowed_calls:
            if result.content:
                return result.content, ""
            messages.append({"role": "user", "content": "(Your internal commentary tool is unavailable here. Answer directly with the requested output, no tool calls.)"})
            continue
        messages.append({"role": "assistant", "content": result.content or "", "tool_calls": allowed_calls})
        for call in allowed_calls:
            fn_name = call.get("function", {}).get("name", "")
            raw_args = call.get("function", {}).get("arguments", "{}")
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
            except json.JSONDecodeError:
                args = {}
            fn = TOOL_FUNCS.get(fn_name)
            if fn is None:
                out = {"error": f"unknown tool {fn_name}"}
            else:
                try:
                    out = fn(ctx, args)
                except Exception as exc:
                    out = {"error": str(exc)[:300]}
            log(ctx.scan_id, f"AI tool call: {fn_name}({json.dumps(args)[:160]})")
            messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": json.dumps(out)[:60_000]})
    return None, "agent loop exceeded max rounds"


def run_structured_agent(ctx: Any, agent_name: str, user_context: str, max_tokens: int | None = None) -> tuple[dict[str, Any], str]:
    """Run a JSON-output agent; returns (json, error). Emits agent events."""
    agent_event(ctx.scan_id, agent_name, "RUNNING")
    data, error = llm(ctx, AGENT_PROMPTS.get(agent_name, ""), user_context, json_mode=True, max_tokens=max_tokens)
    if error:
        agent_event(ctx.scan_id, agent_name, "FAILED", error)
        record_agent(ctx.scan_id, agent_name, "FAILED", error)
        return {}, error
    record_agent(ctx.scan_id, agent_name, "DONE", json.dumps(data)[:2000])
    agent_event(ctx.scan_id, agent_name, "DONE", "analysis complete")
    return data, ""
