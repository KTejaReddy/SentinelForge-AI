"""Single-finding repair & verification (from the Findings UI).

Rebuilds the ScanContext from persisted state (workspace + detection),
restarts the app in the sandbox, then runs the same repair/verify logic
used by the full pipeline.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from config import settings, WORKSPACES_DIR, SCANS_DIR, REPORTS_DIR, UPLOADS_DIR
from database import SessionLocal
from events import log
from models import Finding, Scan
from services.scan_context import ScanContext
from utils.process import find_free_port


def _rebuild_ctx(scan_id: int) -> tuple[ScanContext | None, dict[str, Any] | None]:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return None, None
        project = scan.project
        detection = json.loads(project.detection) if isinstance(project.detection, str) else (project.detection or {})
        options = json.loads(scan.options) if isinstance(scan.options, str) else (scan.options or {})
        workspace = Path(scan.workspace_dir or (Path(WORKSPACES_DIR) / f"scan-{scan_id}"))
    finally:
        db.close()
    ctx = ScanContext(
        scan_id=scan_id,
        project_id=project.id if project else 0,
        project_name=project.name if project else "",
        workspace=workspace,
        original=workspace / "original",
        working=workspace / "working-copy",
        patched=workspace / "patched-copy",
        options=options,
        intensity=scan.intensity or "standard",
    )
    ctx.detection = detection or {}
    return ctx, {"project_id": project.id if project else 0}


def _find_in_bank(ctx: ScanContext, dedup_key: str) -> dict[str, Any] | None:
    from orchestrator.correlate import correlate_findings
    from services.persistence import save_findings
    from tools.base import dedup_key as make_key

    # Rebuild the finding bank from DB findings.
    db = SessionLocal()
    try:
        rows = db.query(Finding).filter_by(scan_id=ctx.scan_id).all()
        bank = []
        for row in rows:
            bank.append({
                "title": row.title, "category": row.category, "severity": row.severity,
                "confidence": row.confidence, "source": row.source,
                "affected_component": row.affected_component, "affected_file": row.affected_file,
                "line_start": row.line_start, "line_end": row.line_end,
                "description": row.description, "why_it_matters": row.why_it_matters,
                "evidence": json.loads(row.evidence) if isinstance(row.evidence, str) else (row.evidence or {}),
                "reproduction": json.loads(row.reproduction) if isinstance(row.reproduction, str) else (row.reproduction or {}),
                "root_cause": row.root_cause, "ai_explanation": row.ai_explanation,
                "recommended_fix": row.recommended_fix, "patch_status": row.patch_status,
                "status": row.status, "provenance": row.provenance, "dedup_key": row.dedup_key, "db_id": row.id,
            })
    finally:
        db.close()
    ctx.findings_bank = bank
    for f in bank:
        if f.get("db_id") and f["dedup_key"] == dedup_key:
            return f
    return None


def repair_single_finding(scan_id: int, finding_id: int, dedup_key: str) -> None:
    ctx, _ = _rebuild_ctx(scan_id)
    if not ctx:
        return
    finding = _find_in_bank(ctx, dedup_key)
    if not finding:
        return
    log(scan_id, f"Single-finding repair started: {finding.get('title')}")
    from orchestrator.build import build_and_start

    build_info = build_and_start(ctx)
    if not build_info.get("base_url") or not build_info.get("started"):
        log(scan_id, "App could not be started for repair", level="warn")
        return
    ctx.runtime = build_info
    ctx.runtime_log = ctx.sandbox.server_logs(400)
    from services.probes.http import discover_routes

    ctx.route_map = {"routes": discover_routes(ctx.working)}
    stats: dict[str, Any] = {"iterations": 0}
    from orchestrator.repair import _repair_one

    _repair_one(ctx, finding, stats)
    from services.persistence import save_findings

    save_findings(scan_id, ctx.findings_bank)
    log(scan_id, "Single-finding repair finished")


def verify_single_finding(scan_id: int, finding_id: int, dedup_key: str) -> None:
    ctx, _ = _rebuild_ctx(scan_id)
    if not ctx:
        return
    finding = _find_in_bank(ctx, dedup_key)
    if not finding:
        return
    from orchestrator.build import build_and_start

    build_info = build_and_start(ctx)
    if not build_info.get("base_url") or not build_info.get("started"):
        return
    ctx.runtime = build_info
    from orchestrator.repair import reproduce_finding

    outcome = reproduce_finding(ctx, finding)
    from agents.verification_agent import decide_verification

    verdict = decide_verification(ctx, finding, {"exploited": True}, outcome, build_pass=True, regression_pass=True)
    log(scan_id, f"Verification result: {verdict['status']}")
    from services.persistence import update_finding

    update_finding(finding_id, patch_status="verified" if verdict["status"] == "FIXED" else finding.get("patch_status"), status="fixed" if verdict["status"] == "FIXED" else finding.get("status"))
