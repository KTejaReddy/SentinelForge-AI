"""Scan Orchestrator - runs the full pipeline for one scan.

Pipeline (per spec §1): upload→extract→fingerprint→build→run→discover→
static→dependency→secrets→dynamic→browser→fuzz→bugs→correlate→AI→repair→
rebuild→verify→report→artifacts.

Robustness rules:
- one failing tool never kills the scan (partial coverage + limitation)
- the original ZIP / original copy are never mutated
- all mutations happen in the working copy
- every step is recorded (scan_steps) and streamed (SSE)
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any, Callable

from config import settings, WORKSPACES_DIR, SCANS_DIR, REPORTS_DIR, UPLOADS_DIR
from database import SessionLocal
from events import agent_event, ev, finding_event, log, progress_event
from models import Evidence, Finding, Patch, Report, Scan, ScanStep, ToolRun, VerificationRun
from orchestrator.state_machine import can_transition
from security import redact_text
from services.scan_context import ScanContext
from services.scoring import compute_scores

# ---------------------------------------------------------------------------
# Steps and weights (deterministic progress)
# ---------------------------------------------------------------------------

STEPS: list[tuple[str, str, float]] = [
    ("EXTRACTING", "Extract project", 4),
    ("ANALYZING", "Detect project", 3),
    ("BUILDING", "Build & start application", 14),
    ("DISCOVERING", "Discover routes & APIs", 4),
    ("STATIC_ANALYSIS", "Static analysis (SAST)", 7),
    ("DEPENDENCY_ANALYSIS", "Dependency analysis", 6),
    ("SECRET_ANALYSIS", "Secrets analysis", 5),
    ("RUNNING", "Native test suite", 6),
    ("DYNAMIC_TESTING", "Dynamic web/API testing", 10),
    ("BROWSER_TESTING", "Browser testing", 8),
    ("FUZZING", "Fuzzing / malformed input", 6),
    ("BUG_HUNTING", "Bug hunting", 5),
    ("CORRELATING", "Correlate findings", 4),
    ("AI_ANALYSIS", "AI root-cause analysis", 8),
    ("REPAIRING", "Automatic repair", 12),
    ("VERIFYING", "Verification & regression", 8),
    ("REPORTING", "Reports & artifacts", 6),
]
TOTAL_WEIGHT = sum(w for _, _, w in STEPS)

_state_lock: dict[int, Any] = {}


def _set_state(scan_id: int, state: str, progress: float | None = None) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan:
            if not can_transition(scan.state, state) and scan.state != state:
                log(scan_id, f"state transition {scan.state}→{state} not in machine (continuing)")
            scan.state = state
            scan.status = state
            if progress is not None:
                scan.progress = round(progress, 2)
            db.commit()
    finally:
        db.close()
    progress_event(scan_id, progress if progress is not None else 0.0, state)
    ev(scan_id, "state", state=state)


def _mark_finished(scan_id: int, status: str, error: str = "") -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = status
            scan.state = status
            scan.finished_at = _utcnow()
            scan.error = error[:2000] or scan.error
            db.commit()
    finally:
        db.close()
    ev(scan_id, "state", state=status, msg=error)


def _utcnow():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


_step_counter = 0


def _step(scan_id: int, key: str, name: str, fn: Callable[[], Any], ctx: ScanContext) -> Any:
    """Run one named step with persistence, events, and error containment."""
    global _step_counter
    _step_counter += 1
    db = SessionLocal()
    row = ScanStep(scan_id=scan_id, name=name, status="RUNNING", order=_step_counter, started_at=_utcnow())
    try:
        db.add(row)
        db.commit()
        db.refresh(row)
    finally:
        db.close()
    row_id = row.id
    log(scan_id, f"▶ {name}")
    try:
        result = fn()
        stored = result
        if isinstance(result, list):
            stored = {"items": _clean(result), "count": len(result)}
        elif result is None:
            stored = {}
        db = SessionLocal()
        try:
            step = db.get(ScanStep, row_id)
            if step:
                step.status = "DONE"
                step.finished_at = _utcnow()
                step.result = _clean(stored)
                db.commit()
        finally:
            db.close()
        return result
    except Exception as exc:
        msg = str(exc)[:800]
        db = SessionLocal()
        try:
            step = db.get(ScanStep, row_id)
            if step:
                step.status = "FAILED"
                step.detail = msg
                step.finished_at = _utcnow()
                db.commit()
        finally:
            db.close()
        log(scan_id, f"✗ {name} failed: {msg}", level="warn")
        ctx.add_limitation(f"{name} step failed: {msg}")
        return None


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in list(value.items())[:200]}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in list(value)[:200]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)[:2000]


def _record_tool_run(scan_id: int, tool: str, status: str, duration_ms: int = 0, exit_code: int | None = None, summary: dict | None = None, output_path: str = "") -> None:
    db = SessionLocal()
    try:
        db.add(ToolRun(scan_id=scan_id, tool=tool, status=status, duration_ms=duration_ms, exit_code=exit_code, summary=summary or {}, output_path=output_path))
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------


def run_scan(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        project = scan.project
        options = json.loads(scan.options) if isinstance(scan.options, str) else (scan.options or {})
        intensity = scan.intensity or options.get("intensity", settings.default_intensity)
    finally:
        db.close()

    workspace = Path(WORKSPACES_DIR) / f"scan-{scan_id}"
    original, working, patched = workspace / "original", workspace / "working-copy", workspace / "patched-copy"
    for d in (original, working, patched, workspace / "artifacts"):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)

    ctx = ScanContext(
        scan_id=scan_id,
        project_id=project.id if project else 0,
        project_name=project.name if project else "",
        workspace=workspace,
        original=original,
        working=working,
        patched=patched,
        options=options,
        intensity=intensity,
    )
    ctx.sandbox = ctx.sandbox  # built in __post_init__

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.workspace_dir = str(workspace)
            db.commit()
    finally:
        db.close()

    total_done = 0.0

    def advance(weight: float) -> None:
        nonlocal total_done
        total_done += weight
        _set_state(scan_id, "RUNNING", total_done / TOTAL_WEIGHT * 100)

    try:
        # ---- 1. extract ------------------------------------------------------
        from security import secure_extract_zip

        upload_dir = Path(UPLOADS_DIR)
        zip_path = None
        if project:
            cand = upload_dir / f"{project.id}.zip"
            if cand.exists():
                zip_path = cand
        if zip_path is None:
            raise RuntimeError("project ZIP missing from uploads")

        def _extract():
            extracted = secure_extract_zip(zip_path.read_bytes(), original)
            # copy to working copy (patched copy starts as a copy of working later)
            _copytree(original, working)
            return {"files": len(extracted)}

        _set_state(scan_id, "EXTRACTING", total_done / TOTAL_WEIGHT * 100)
        _step(scan_id, "EXTRACTING", "Secure extraction", _extract, ctx)
        log(scan_id, "Project extracted - zip-slip & bomb guards passed")
        advance(STEPS[0][2])

        # ---- 2. detection ------------------------------------------------------
        from services.project_detector import detect_project

        def _detect():
            det = detect_project(working)
            ctx.detection = det
            db = SessionLocal()
            try:
                proj = db.get(type(project), project.id) if project else None
                if proj:
                    proj.project_type = det.get("project_type", "unknown")
                    proj.detection = json.dumps(det)
                    proj.status = "ANALYZED"
                    db.commit()
            finally:
                db.close()
            return {"type": det.get("project_type"), "languages": det.get("languages"), "frameworks": det.get("frameworks"), "entrypoints": det.get("entrypoints")}

        _set_state(scan_id, "ANALYZING", total_done / TOTAL_WEIGHT * 100)
        det_result = _step(scan_id, "ANALYZING", "Project fingerprinting", _detect, ctx)
        if det_result:
            for fw in (ctx.detection.get("frameworks") or [])[:8]:
                log(scan_id, f"Detected: {fw}")
        advance(STEPS[1][2])

        # ---- 3. build & run ------------------------------------------------------
        from orchestrator.build import build_and_start

        build_info = _step(scan_id, "BUILDING", "Build & start application", lambda: build_and_start(ctx), ctx)
        if build_info and build_info.get("base_url"):
            ctx.runtime = build_info
            log(scan_id, f"Application started: {build_info['base_url']}")
        else:
            ctx.runtime = {"base_url": None, "started": False}
            log(scan_id, "Application could not be started - continuing with static-only coverage", level="warn")
            ctx.add_limitation("Application did not start; dynamic/browser/fuzz steps will be limited")
        advance(STEPS[2][2])

        # ---- 4. route discovery ------------------------------------------------------
        from services.probes.http import discover_routes

        def _discover():
            routes = discover_routes(working)
            ctx.route_map = {"routes": routes, "count": len(routes)}
            return {"routes": len(routes)}

        _set_state(scan_id, "DISCOVERING", total_done / TOTAL_WEIGHT * 100)
        disc = _step(scan_id, "DISCOVERING", "Route & API discovery", _discover, ctx)
        if disc:
            log(scan_id, f"{disc.get('routes', 0)} route candidates discovered from source")
        advance(STEPS[3][2])

        # ---- 5. static analysis ---------------------------------------------------
        if ctx.enabled("static_analysis"):
            def _static():
                from tools.bandit import BanditAdapter
                from tools.semgrep import SemgrepAdapter

                out = []
                out.extend(SemgrepAdapter().execute(ctx))
                out.extend(BanditAdapter().execute(ctx))
                return out

            _set_state(scan_id, "STATIC_ANALYSIS", total_done / TOTAL_WEIGHT * 100)
            findings = _step(scan_id, "STATIC_ANALYSIS", "Static analysis (SAST)", _static, ctx) or []
            _extend_bank(ctx, findings)
            for f in findings:
                finding_event(scan_id, f)
            advance(STEPS[4][2])
        else:
            advance(STEPS[4][2])

        # ---- 6. dependency analysis -------------------------------------------------
        if ctx.enabled("dependency_analysis"):
            def _deps():
                from tools.osv_scanner import OsvScannerAdapter
                from tools.trivy import TrivyAdapter

                out = []
                out.extend(TrivyAdapter().execute(ctx))
                out.extend(OsvScannerAdapter().execute(ctx))
                return out

            _set_state(scan_id, "DEPENDENCY_ANALYSIS", total_done / TOTAL_WEIGHT * 100)
            findings = _step(scan_id, "DEPENDENCY_ANALYSIS", "Dependency analysis", _deps, ctx) or []
            _extend_bank(ctx, findings)
            for f in findings:
                finding_event(scan_id, f)
            advance(STEPS[5][2])
        else:
            advance(STEPS[5][2])

        # ---- 7. secrets --------------------------------------------------------------
        if ctx.enabled("secrets_detection"):
            def _secrets():
                from tools.gitleaks import GitleaksAdapter

                return GitleaksAdapter().execute(ctx)

            _set_state(scan_id, "SECRET_ANALYSIS", total_done / TOTAL_WEIGHT * 100)
            findings = _step(scan_id, "SECRET_ANALYSIS", "Secrets analysis", _secrets, ctx) or []
            _extend_bank(ctx, findings)
            for f in findings:
                finding_event(scan_id, f)
            advance(STEPS[6][2])
        else:
            advance(STEPS[6][2])

        # ---- 8. native tests ------------------------------------------------------------
        if ctx.enabled("bug_hunting"):
            def _tests():
                from tools.native_tests import NativeTestAdapter

                return NativeTestAdapter().execute(ctx)

            _set_state(scan_id, "RUNNING", total_done / TOTAL_WEIGHT * 100)
            findings = _step(scan_id, "RUNNING", "Project-native test suite", _tests, ctx) or []
            _extend_bank(ctx, findings)
            for f in findings:
                finding_event(scan_id, f)
            advance(STEPS[7][2])
        else:
            advance(STEPS[7][2])

        # ---- 9. dynamic testing ------------------------------------------------------------
        if ctx.enabled("dynamic_testing") and ctx.runtime.get("base_url"):
            def _dynamic():
                from tools.custom_probes import CustomProbeAdapter
                from tools.ffuf import FfufAdapter
                from tools.nuclei import NucleiAdapter
                from tools.zap import ZapAdapter

                out = []
                out.extend(CustomProbeAdapter().execute(ctx))
                if intensity in ("aggressive", "maximum_safe"):
                    out.extend(FfufAdapter().execute(ctx))
                    out.extend(NucleiAdapter().execute(ctx))
                out.extend(ZapAdapter().execute(ctx))
                return out

            _set_state(scan_id, "DYNAMIC_TESTING", total_done / TOTAL_WEIGHT * 100)
            findings = _step(scan_id, "DYNAMIC_TESTING", "Dynamic web/API security testing", _dynamic, ctx) or []
            _extend_bank(ctx, findings)
            for f in findings:
                finding_event(scan_id, f)
            advance(STEPS[8][2])
        else:
            ctx.add_limitation("Dynamic testing skipped (disabled or app not running)")
            advance(STEPS[8][2])

        # ---- 10. browser testing -----------------------------------------------------------
        if ctx.enabled("browser_testing") and ctx.runtime.get("base_url"):
            def _browser():
                from tools.playwright_probe import PlaywrightProbeAdapter

                return PlaywrightProbeAdapter().execute(ctx)

            _set_state(scan_id, "BROWSER_TESTING", total_done / TOTAL_WEIGHT * 100)
            findings = _step(scan_id, "BROWSER_TESTING", "Browser-based testing", _browser, ctx) or []
            _extend_bank(ctx, findings)
            for f in findings:
                finding_event(scan_id, f)
            advance(STEPS[9][2])
        else:
            ctx.add_limitation("Browser testing skipped (disabled or app not running)")
            advance(STEPS[9][2])

        # ---- 11. fuzzing --------------------------------------------------------------------
        if ctx.enabled("fuzzing") and ctx.runtime.get("base_url"):
            def _fuzz():
                from tools.fuzz import FuzzAdapter

                return FuzzAdapter().execute(ctx)

            _set_state(scan_id, "FUZZING", total_done / TOTAL_WEIGHT * 100)
            findings = _step(scan_id, "FUZZING", "Fuzzing / malformed-input testing", _fuzz, ctx) or []
            _extend_bank(ctx, findings)
            for f in findings:
                finding_event(scan_id, f)
            advance(STEPS[10][2])
        else:
            advance(STEPS[10][2])

        # ---- 12. bug hunting ------------------------------------------------------------------
        _set_state(scan_id, "BUG_HUNTING", total_done / TOTAL_WEIGHT * 100)

        def _bugs():
            from agents.simple_agents import run_bug_hunter_agent

            return run_bug_hunter_agent(ctx)

        _step(scan_id, "BUG_HUNTING", "Bug hunting (AI-assisted)", _bugs, ctx)
        advance(STEPS[11][2])

        # ---- 13. correlate ----------------------------------------------------------------------
        _set_state(scan_id, "CORRELATING", total_done / TOTAL_WEIGHT * 100)

        def _correlate():
            from orchestrator.correlate import correlate_findings

            correlated = correlate_findings(ctx)
            ctx.findings_bank = correlated
            return {"total": len(correlated), "by_severity": _severity_counts(correlated)}

        corr = _step(scan_id, "CORRELATING", "Correlate & deduplicate findings", _correlate, ctx) or {}
        if corr:
            log(scan_id, f"{corr.get('total', 0)} findings after correlation")
        advance(STEPS[12][2])

        # ---- 14. AI analysis ----------------------------------------------------------------------
        _set_state(scan_id, "AI_ANALYSIS", total_done / TOTAL_WEIGHT * 100)
        ai_phase_start = time.time()
        ai_budget = min(settings.ai_phase_timeout_seconds, 60)  # cap at 60s to leave time for repair

        def _ai():
            from agents.recon_agent import run_recon_agent
            from agents.security_agent import run_security_agent
            from agents.simple_agents import run_ai_summary_agents
            from orchestrator.analyze import run_root_cause_analysis

            def _ai_budget_ok() -> bool:
                return (time.time() - ai_phase_start) < ai_budget

            # Only run the security agent (correlates findings) - skip recon and summary agents
            # to save rate-limit budget for repair. The security agent is the most valuable.
            if _ai_budget_ok():
                run_security_agent(ctx, ctx.findings_bank)
            # Root cause analysis for top 2 findings only
            if _ai_budget_ok():
                run_root_cause_analysis(ctx, deadline=ai_phase_start + ai_budget)
            elapsed = time.time() - ai_phase_start
            if elapsed >= ai_budget:
                log(scan_id, f"AI analysis time budget exhausted ({elapsed:.0f}s/{ai_budget}s)")
            return {"ai_calls": ctx.ai_calls, "cost_usd": round(ctx.ai_cost_usd, 4)}

        ai_info = _step(scan_id, "AI_ANALYSIS", "AI reasoning & root-cause analysis", _ai, ctx) or {}
        if ai_info:
            log(scan_id, f"AI analysis: {ai_info.get('ai_calls', 0)} calls, ~${ai_info.get('cost_usd', 0)}")
        advance(STEPS[13][2])

        # ---- 15. repair -----------------------------------------------------------------------------
        if ctx.enabled("automatic_repair"):
            _set_state(scan_id, "REPAIRING", total_done / TOTAL_WEIGHT * 100)
            repair_start = time.time()
            repair_budget = 120  # 2 minutes max for repair phase (deterministic repairs are fast)

            def _repair():
                from orchestrator.repair import run_repair_loop

                return run_repair_loop(ctx, deadline=repair_start + repair_budget)

            repair_info = _step(scan_id, "REPAIRING", "Automatic repair", _repair, ctx) or {}
            if repair_info:
                log(scan_id, f"Repair: {repair_info.get('patched', 0)} patched, {repair_info.get('verified', 0)} verified")
            advance(STEPS[14][2])
        else:
            advance(STEPS[14][2])

        # ---- 16. verification / regression ----------------------------------------------------------
        _set_state(scan_id, "VERIFYING", total_done / TOTAL_WEIGHT * 100)

        def _verify():
            from orchestrator.repair import run_final_regression

            return run_final_regression(ctx)

        _step(scan_id, "VERIFYING", "Verification & regression", _verify, ctx)
        advance(STEPS[15][2])

        # ---- 17. reports & artifacts ----------------------------------------------------------------
        _set_state(scan_id, "REPORTING", total_done / TOTAL_WEIGHT * 100)

        def _report():
            from orchestrator.report import finalize_scan

            return finalize_scan(ctx)

        _step(scan_id, "REPORTING", "Reports, scoring & artifacts", _report, ctx)
        advance(STEPS[16][2])

        _mark_finished(scan_id, "COMPLETED")
        log(scan_id, "Scan completed")
        ev(scan_id, "scan_complete", state="COMPLETED")

    except Exception as exc:
        import traceback

        _mark_finished(scan_id, "FAILED", str(exc))
        log(scan_id, f"Scan failed: {exc}", level="error")
        ev(scan_id, "scan_error", msg=str(exc))
        traceback.print_exc()
    finally:
        try:
            ctx.sandbox.cleanup()
        except Exception:
            pass
        _set_state(scan_id, _current_state(scan_id), None)


def _current_state(scan_id: int) -> str:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        return scan.state if scan else "FAILED"
    finally:
        db.close()


def _extend_bank(ctx: ScanContext, findings: Any) -> None:
    """Extend the finding bank, dropping any non-dict entries defensively."""
    if not findings:
        return
    if isinstance(findings, dict):
        findings = [findings]
    for f in findings:
        if isinstance(f, dict):
            ctx.findings_bank.append(f)
        else:
            log(ctx.scan_id, f"Dropped non-finding entry from tool output: {str(f)[:200]}", level="warn")


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _copytree(src: Path, dst: Path) -> None:
    for item in src.rglob("*"):
        if item.is_symlink():
            continue
        rel = item.relative_to(src)
        if any(part in {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", ".next", "target", "coverage"} for part in rel.parts):
            continue
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(item, target)
            except OSError:
                pass
