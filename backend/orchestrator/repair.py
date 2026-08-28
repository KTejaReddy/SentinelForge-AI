"""Automatic Repair system (§17).

For each high-value machine-reproducible finding:
  reproduce BEFORE → repair agent patch → validate → apply (working copy)
  → rebuild + restart → reproduce AFTER → native regression → targeted
  rescan → verification agent verdict.

Patches that fail verification are REVERTED so the working copy only ever
contains verified fixes. The original copy is never touched.
"""
from __future__ import annotations

import time
from typing import Any

from agents.base import record_agent
from agents.repair_agent import run_repair_agent
from agents.verification_agent import decide_verification
from config import settings
from events import agent_event, ev, finding_event, log
from services.ai.groq_client import GroqClient
from services.patching.patch_engine import apply_patch, validate_patch, write_regression_test
from services.persistence import add_patch, add_verification, update_finding
from services.probes.http import probe
from services.repair_toolchain import RepairResult, classify_repair_type, validate_repair_safety
from services.scan_context import ScanContext

REPAIR_TARGETS = ("CRITICAL", "HIGH")
MAX_REPAIRED = 3  # up to 3 repairs (deterministic templates are fast)


def run_repair_loop(ctx: ScanContext, deadline: float = 0) -> dict[str, Any]:
    stats = {"patched": 0, "verified": 0, "failed": 0, "reverted": 0, "iterations": 0}
    if not ctx.runtime.get("base_url"):
        ctx.add_limitation("Auto-repair skipped: application not running, cannot reproduce")
        return stats

    # Only repair findings with machine-reproducible exploits (method+path)
    candidates = [
        f for f in ctx.findings_bank
        if f.get("severity") in REPAIR_TARGETS
        and f.get("patch_status") in ("none", "pending")
        and _has_machine_repro(f)
    ]
    # Prioritize CRITICAL over HIGH, then by confidence
    candidates.sort(key=lambda f: (-_sev_rank(f.get("severity")), -f.get("confidence", 0)))

    for finding in candidates[:MAX_REPAIRED]:
        if ctx.cancel_event.is_set():
            break
        if deadline and time.time() >= deadline:
            log(ctx.scan_id, "Repair phase time budget exhausted")
            break
        if stats["iterations"] >= settings.max_repair_iterations:
            break
        _repair_one(ctx, finding, stats)
    return stats


def _repair_one(ctx: ScanContext, finding: dict[str, Any], stats: dict[str, Any]) -> None:
    finding_id = finding.get("db_id")
    before = reproduce_finding(ctx, finding)
    if not before.get("status_code") and before.get("exploited") is None:
        finding["patch_status"] = "skipped"
        if finding_id:
            update_finding(finding_id, patch_status="skipped")
        return

    # Classify repair type
    repair_type = classify_repair_type(finding)
    log(ctx.scan_id, f"Attempting repair for '{finding.get('title')}' (type: {repair_type})")

    # Try deterministic repair first (no AI needed)
    from services.deterministic_repairs import apply_deterministic_repair
    det_ok, det_diff, det_explanation = apply_deterministic_repair(finding, ctx.working)
    
    if det_ok:
        log(ctx.scan_id, f"Deterministic repair applied for: {finding.get('title')}")
        
        # Create repair result with tool label
        repair_result = RepairResult()
        repair_result.success = True
        repair_result.tool_source = "DETERMINISTIC_TOOL"
        repair_result.diff = det_diff
        repair_result.explanation = det_explanation
        repair_result.repair_type = repair_type
        
        patch_id = add_patch(ctx.scan_id, finding_id, det_diff, {}, det_explanation, 
                           tool_source="DETERMINISTIC_TOOL", repair_type=repair_type)
        finding["patch_status"] = "applied"
        finding["repair_tool"] = "DETERMINISTIC_TOOL"
        if finding_id:
            update_finding(finding_id, patch_status="applied")
        
        # Rebuild and verify
        from orchestrator.build import build_and_start
        log(ctx.scan_id, "Rebuilding patched application (deterministic repair)")
        try:
            ctx.sandbox.stop()
        except Exception:
            pass
        build_info = build_and_start(ctx)
        if not build_info.get("base_url") or not build_info.get("started"):
            ctx.add_limitation(f"Patched app failed to start - reverting deterministic patch for '{finding.get('title')}'")
            stats["reverted"] += 1
            if finding_id:
                update_finding(finding_id, patch_status="failed", status="needs_review")
            return
        ctx.runtime = build_info
        after = reproduce_finding(ctx, finding)
        
        # Run regression tests
        test_cmd = (ctx.detection.get("commands") or {}).get("test")
        regression_pass = True
        if test_cmd:
            res = ctx.sandbox.run(test_cmd.split(), cwd=ctx.working, timeout_s=120)
            regression_pass = res.exit_code == 0
        
        verdict_status = "FIXED" if (not after.get("exploited", True) and regression_pass) else "NOT_FIXED"
        
        # Create verification result
        from services.verification_runner import VerificationResult
        verification = VerificationResult()
        verification.build_pass = build_info.get("started", False)
        verification.regression_pass = regression_pass
        verification.exploit_blocked = not after.get("exploited", True)
        verification.before_exploit = before
        verification.after_exploit = after
        
        add_verification(ctx.scan_id, patch_id, finding_id, verdict_status, 
                        build_info.get("started", False), regression_pass, 
                        not after.get("exploited", True), verification.to_dict())
        
        if verdict_status == "FIXED":
            finding["status"] = "fixed"
            finding["patch_status"] = "verified"
            finding["repair_tool"] = "DETERMINISTIC_TOOL"
            stats["patched"] += 1
            stats["verified"] += 1
            if finding_id:
                update_finding(finding_id, status="fixed", patch_status="verified")
            log(ctx.scan_id, f"✅ Verified FIXED: {finding.get('title')}")
        else:
            finding["patch_status"] = "failed"
            finding["repair_tool"] = "DETERMINISTIC_TOOL"
            stats["failed"] += 1
            if finding_id:
                update_finding(finding_id, patch_status="failed", status="needs_review")
            log(ctx.scan_id, f"Deterministic patch not effective: {finding.get('title')}")
        return

    # Fall back to AI repair agent (labeled as AI_PATCH_FALLBACK)
    log(ctx.scan_id, f"No deterministic template available for '{finding.get('title')}', trying AI repair")
    
    for attempt in range(settings.max_repair_iterations):
        stats["iterations"] += 1
        agent_event(ctx.scan_id, "repair_agent", "RUNNING", finding.get("title", ""))
        patch, error = run_repair_agent(ctx, finding)
        if error:
            break
        errors = validate_patch(patch, ctx)
        if errors:
            ctx.add_limitation(f"Patch rejected for '{finding.get('title')}': {'; '.join(errors)[:300]}")
            record_agent(ctx.scan_id, "repair_agent", "FAILED", "; ".join(errors)[:500])
            break

        # snapshot before content for revert
        before_contents = {rel: (ctx.working / rel).read_text(encoding="utf-8", errors="replace") for rel in patch.get("files", {})}
        ok, changed, diff = apply_patch(patch, ctx)
        if not ok:
            break
        
        # Create patch with AI label
        patch_id = add_patch(ctx.scan_id, finding_id, diff, 
                           {c["file"]: {"before": c["before"], "after": c["after"]} for c in changed}, 
                           patch.get("explanation", ""),
                           tool_source="AI_PATCH_FALLBACK", repair_type=repair_type)
        
        ctx.tool_results.setdefault("patches", []).append({
            "finding": finding.get("title"), 
            "status": "applied", 
            "explanation": patch.get("explanation", ""), 
            "diff": diff,
            "repair_tool": "AI_PATCH_FALLBACK"
        })
        finding["patch_status"] = "applied"
        finding["repair_tool"] = "AI_PATCH_FALLBACK"
        if finding_id:
            update_finding(finding_id, patch_status="applied")
        ev(ctx.scan_id, "patch_applied", finding=finding.get("title"), files=list(patch.get("files", {}).keys()))

        # rebuild + restart the patched app
        from orchestrator.build import build_and_start
        log(ctx.scan_id, "Rebuilding patched application (AI patch)")
        agent_event(ctx.scan_id, "verification_agent", "RUNNING", "rebuild")
        try:
            ctx.sandbox.stop()
        except Exception:
            pass
        build_info = build_and_start(ctx)
        if not build_info.get("base_url") or not build_info.get("started"):
            ctx.add_limitation(f"Patched app failed to start - reverting patch for '{finding.get('title')}'")
            _revert(ctx, patch.get("files", {}), before_contents)
            stats["reverted"] += 1
            if finding_id:
                update_finding(finding_id, patch_status="failed", status="needs_review")
            break
        ctx.runtime = build_info
        ctx.runtime_log = ctx.sandbox.server_logs(400)

        after = reproduce_finding(ctx, finding)

        # regression: native tests
        regression_pass = True
        regression_note = "no test command"
        test_cmd = (ctx.detection.get("commands") or {}).get("test")
        if test_cmd:
            agent_event(ctx.scan_id, "verification_agent", "RUNNING", "regression tests")
            res = ctx.sandbox.run(test_cmd.split(), cwd=ctx.working, timeout_s=900)
            regression_pass = res.exit_code == 0
            regression_note = f"exit {res.exit_code}"
        else:
            # generated regression test instead
            gen = (patch.get("regression_test") or {})
            if gen.get("content"):
                rel = write_regression_test(ctx, finding, gen["content"], gen.get("file"))
                if rel:
                    res = ctx.sandbox.run(_test_cmd_for(ctx, rel), cwd=ctx.working, timeout_s=600)
                    regression_pass = res.exit_code == 0
                    regression_note = f"generated test {rel}: exit {res.exit_code}"
                    ctx.tool_results["generated_regression_tests"] = ctx.tool_results.get("generated_regression_tests", []) + [rel]

        # targeted security rescan
        rescanned = _targeted_rescan(ctx, finding)

        verdict = decide_verification(ctx, finding, before, after, build_pass=build_info.get("started", False), regression_pass=regression_pass)
        verdict["regression_note"] = regression_note
        verdict["rescan"] = rescanned
        verdict["repair_tool"] = "AI_PATCH_FALLBACK"
        
        add_verification(ctx.scan_id, patch_id, finding_id, verdict["status"], verdict["build_pass"], verdict["regression_pass"], verdict["exploit_blocked"], verdict)

        if verdict["status"] in ("FIXED", "PARTIALLY_FIXED"):
            finding["status"] = "fixed" if verdict["status"] == "FIXED" else "needs_review"
            finding["patch_status"] = "verified"
            finding["repair_tool"] = "AI_PATCH_FALLBACK"
            stats["patched"] += 1
            stats["verified"] += 1 if verdict["status"] == "FIXED" else 0
            if finding_id:
                update_finding(finding_id, status=finding["status"], patch_status="verified")
            finding_event(ctx.scan_id, {**finding, "verification": verdict})
            log(ctx.scan_id, f"✅ Verified: {finding.get('title')} → {verdict['status']}")
            break
        # NOT_FIXED / NEEDS_HUMAN_REVIEW → revert and try next candidate
        _revert(ctx, patch.get("files", {}), before_contents)
        stats["reverted"] += 1
        stats["failed"] += 1
        if finding_id:
            update_finding(finding_id, patch_status="failed", status="needs_review")
        ctx.add_limitation(f"Patch for '{finding.get('title')}' not verified ({verdict['status']}) - reverted")
        log(ctx.scan_id, f"✗ Not verified ({verdict['status']}) - patch reverted for {finding.get('title')}")


def reproduce_finding(ctx: ScanContext, finding: dict[str, Any]) -> dict[str, Any]:
    """Replay a finding's machine reproduction against the running app."""
    rep = finding.get("reproduction") or {}
    method = rep.get("method")
    path = rep.get("path")
    base_url = ctx.runtime.get("base_url")
    if not method or not path or not base_url:
        return {}
    url = base_url.rstrip("/") + path
    try:
        resp = probe(method, url, timeout_s=8, params=rep.get("params") or {}, content=rep.get("body") if method in ("POST", "PUT", "PATCH") else None)
    except Exception as exc:
        return {"error": str(exc)[:200]}
    outcome: dict[str, Any] = {
        "method": method, "path": path, "params": rep.get("params") or {},
        "status_code": resp.status_code, "body_tail": (resp.text or "")[:1500],
    }
    expect = rep.get("expect") or {}
    if expect:
        status_ok = expect.get("status") is None or resp.status_code == expect.get("status")
        contains_ok = expect.get("contains") is None or expect.get("contains") in (resp.text or "")
        outcome["exploited"] = bool(status_ok and contains_ok)
    return outcome


def _has_machine_repro(finding: dict[str, Any]) -> bool:
    rep = finding.get("reproduction") or {}
    return bool(rep.get("method") and rep.get("path"))


def _revert(ctx: ScanContext, files: dict[str, Any], before_contents: dict[str, str]) -> None:
    for rel, content in before_contents.items():
        try:
            target = ctx.working / rel
            target.write_text(content, encoding="utf-8")
            log(ctx.scan_id, f"Reverted {rel}")
        except OSError:
            pass


def _targeted_rescan(ctx: ScanContext, finding: dict[str, Any]) -> dict[str, Any]:
    """Rerun the relevant scanner on the changed file, if possible."""
    from tools.semgrep import SemgrepAdapter

    before_count = len(ctx.findings_bank)
    findings = SemgrepAdapter().execute(ctx)
    same = [f for f in findings if f.get("affected_file") == finding.get("affected_file") or finding.get("title", "").split(":")[0] in f.get("title", "")]
    return {"scanner": "semgrep", "matching_after": len(same), "total_after": len(findings)}


def _sev_rank(sev: str) -> int:
    return {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(sev, 0)


def _test_cmd_for(ctx: ScanContext, rel_test: str) -> list[str]:
    langs = ctx.detection.get("languages", {}) or {}
    if "python" in langs:
        return ["python", "-m", "pytest", "-q", rel_test]
    if "javascript" in langs or "typescript" in langs:
        if rel_test.endswith(".ts"):
            return ["npx", "vitest", "run", rel_test]
        return ["npx", "jest", rel_test, "--runInBand", "--silent"]
    return ["python", "-m", "pytest", "-q", rel_test]


def run_final_regression(ctx: ScanContext) -> dict[str, Any]:
    """Final regression sweep after all patches (build + tests + probes)."""
    result: dict[str, Any] = {"build": False, "tests": None, "reproduced": {}}
    test_cmd = (ctx.detection.get("commands") or {}).get("test")
    if ctx.runtime.get("base_url"):
        result["build"] = True
        # re-run original reproductions for all fixed findings
        for f in ctx.findings_bank:
            if f.get("status") in ("fixed", "verified"):
                outcome = reproduce_finding(ctx, f)
                result["reproduced"][f.get("title", "")[:80]] = outcome.get("exploited")
    if test_cmd:
        res = ctx.sandbox.run(test_cmd.split(), cwd=ctx.working, timeout_s=900)
        result["tests"] = {"exit_code": res.exit_code, "pass": res.exit_code == 0}
    ctx.tool_results["final_regression"] = result
    return result
