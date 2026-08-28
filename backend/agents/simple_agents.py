"""Lightweight agents that turn deterministic tool output into structured
AI analysis. Each only ever sees relevant context, and each degrades to a
recorded skip when Groq is unavailable."""
from __future__ import annotations

from typing import Any

from agents.base import run_structured_agent
from events import log
from services.ai.context import summarize_findings, summarize_logs
from services.scan_context import ScanContext


def run_api_agent(ctx: ScanContext) -> dict[str, Any]:
    routes = (ctx.route_map or {}).get("routes", [])
    if not routes:
        return {}
    user = "Discovered routes:\n" + "\n".join(f"- {r.get('methods')} {r.get('path')} [{r.get('source_file')}:{r.get('line')}] auth_hint={r.get('auth_hint')}" for r in routes[:50])
    user += "\n\nDynamic findings relevant to APIs:\n" + summarize_findings([f for f in ctx.findings_bank if f.get("category") in ("api_security", "authentication", "authorization")], limit=20)
    data, _ = run_structured_agent(ctx, "api_agent", user, max_tokens=2000)
    return data


def run_browser_agent(ctx: ScanContext) -> dict[str, Any]:
    browser = ctx.tool_results.get("browser", {})
    if not browser:
        return {}
    user = "Browser engine results:\n" + str(browser)[:3000]
    user += "\n\nRelevant browser findings:\n" + summarize_findings([f for f in ctx.findings_bank if f.get("source") == "browser"], limit=20)
    data, _ = run_structured_agent(ctx, "browser_agent", user, max_tokens=1500)
    return data


def run_bug_hunter_agent(ctx: ScanContext) -> dict[str, Any]:
    logs = summarize_logs(ctx.runtime_log)
    findings = summarize_findings([f for f in ctx.findings_bank if f.get("category") == "reliability"], limit=20)
    user = f"Runtime logs (tail):\n{logs}\n\nReliability findings:\n{findings}\n\nFind bugs as JSON."
    data, _ = run_structured_agent(ctx, "bug_hunter_agent", user, max_tokens=2000)
    return data


def run_dependency_agent(ctx: ScanContext) -> dict[str, Any]:
    dep_findings = [f for f in ctx.findings_bank if f.get("category") == "dependencies"]
    if not dep_findings:
        return {}
    user = "Dependency findings:\n" + summarize_findings(dep_findings, limit=30) + "\n\nPrioritize as JSON."
    data, _ = run_structured_agent(ctx, "dependency_agent", user, max_tokens=1500)
    return data


def run_secret_agent(ctx: ScanContext) -> dict[str, Any]:
    sec_findings = [f for f in ctx.findings_bank if f.get("category") == "secrets"]
    if not sec_findings:
        return {}
    user = "Secret findings:\n" + summarize_findings(sec_findings, limit=30) + "\n\nClassify as JSON."
    data, _ = run_structured_agent(ctx, "secret_agent", user, max_tokens=1500)
    return data


def run_fuzz_agent(ctx: ScanContext) -> dict[str, Any]:
    fuzz_findings = [f for f in ctx.findings_bank if f.get("category") in ("reliability", "input_validation")]
    if not fuzz_findings:
        return {}
    user = "Malformed-input findings:\n" + summarize_findings(fuzz_findings, limit=20) + "\n\nAnalyze and suggest tests as JSON."
    data, _ = run_structured_agent(ctx, "fuzz_agent", user, max_tokens=1500)
    return data


def run_business_logic_agent(ctx: ScanContext) -> dict[str, Any]:
    routes = (ctx.route_map or {}).get("routes", [])
    forms = (ctx.tool_results.get("browser") or {}).get("forms", [])
    if not routes and not forms:
        return {}
    user = (
        "Routes:\n" + "\n".join(f"- {r.get('methods')} {r.get('path')}" for r in routes[:40]) +
        "\n\nForms:\n" + str(forms)[:2000] +
        "\n\nLook for business-logic flaws as JSON."
    )
    data, _ = run_structured_agent(ctx, "business_logic_agent", user, max_tokens=2000)
    return data


def run_ai_summary_agents(ctx: ScanContext) -> None:
    """Run all lightweight agents that depend on gathered tool results."""
    run_api_agent(ctx)
    run_browser_agent(ctx)
    run_bug_hunter_agent(ctx)
    run_dependency_agent(ctx)
    run_secret_agent(ctx)
    run_fuzz_agent(ctx)
    run_business_logic_agent(ctx)
    log(ctx.scan_id, "AI summary agents complete")
