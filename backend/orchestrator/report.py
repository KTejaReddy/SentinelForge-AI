"""Finalization - scores, findings persistence, patched copy, reports, zips."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from config import settings
from database import SessionLocal
from events import log
from models import Report, Scan
from security import make_zip
from services.persistence import add_report, save_findings
from services.reporting import build_reports, create_artifacts, write_reports
from services.scan_context import ScanContext
from services.scoring import compute_scores


def finalize_scan(ctx: ScanContext) -> dict[str, Any]:
    # ---- scores ------------------------------------------------------------
    scores = compute_scores(ctx.findings_bank, ctx.tool_results)
    counts = _counts(ctx.findings_bank)

    # ---- persist findings ----------------------------------------------------
    save_findings(ctx.scan_id, ctx.findings_bank)

    # ---- patched copy (only verified fixes live in working copy) -------------
    _copy_to_patched(ctx)

    # ---- reports + artifacts --------------------------------------------------
    summary = {
        "counts": counts,
        "scores": scores,
        "ai": {"calls": ctx.ai_calls, "cost_usd": round(ctx.ai_cost_usd, 6), "tokens": ctx.ai_tokens},
        "attack_graph": _build_attack_graph(ctx),
        "limitations": ctx.limitations,
        "sandbox_mode": ctx.sandbox.mode,
        "tools_executed": list(ctx.tool_results.keys()),
    }
    reports = build_reports(ctx, scores, summary)
    write_reports(ctx, reports)
    artifacts = create_artifacts(ctx)

    # ---- scan summary row -------------------------------------------------------
    db = SessionLocal()
    try:
        scan = db.get(Scan, ctx.scan_id)
        if scan:
            scan.scores = json.dumps(scores)
            scan.summary = json.dumps(summary)
            scan.status = "COMPLETED"
            db.commit()
            for rtype, path in (("executive", artifacts.get("reports", "")), ("artifacts", artifacts.get("patched", ""))):
                if path:
                    add_report(ctx.scan_id, rtype, str(path))
    finally:
        db.close()
    log(ctx.scan_id, f"Reports written; artifacts: {', '.join(str(v) for v in artifacts.values())}")
    return {"scores": scores, "counts": counts, "artifacts": {k: str(v) for k, v in artifacts.items()}}


def _copy_to_patched(ctx: ScanContext) -> None:
    shutil.rmtree(ctx.patched, ignore_errors=True)
    ctx.patched.mkdir(parents=True, exist_ok=True)
    for item in ctx.working.rglob("*"):
        if item.is_symlink():
            continue
        rel = item.relative_to(ctx.working)
        if any(part in {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", ".next", "target", "coverage", ".sf-home"} for part in rel.parts):
            continue
        target = ctx.patched / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(item, target)
            except OSError:
                pass


def _build_attack_graph(ctx: ScanContext) -> list[dict[str, Any]]:
    """Deterministic attack graph: app → component → test → finding → patch."""
    nodes: list[dict[str, Any]] = [{"id": "app", "label": "Application", "kind": "root"}]
    edges: list[dict[str, Any]] = []
    for i, f in enumerate(ctx.findings_bank):
        comp = f.get("affected_component") or f.get("affected_file") or "component"
        cid, tid, fid = f"comp-{i}", f"test-{i}", f"f-{i}"
        nodes.append({"id": cid, "label": comp[:60], "kind": "component"})
        nodes.append({"id": tid, "label": f.get("source", "test"), "kind": "test"})
        nodes.append({"id": fid, "label": f.get("title", "")[:80], "kind": "finding", "severity": f.get("severity"), "status": f.get("status")})
        edges.append({"source": "app", "target": cid, "label": "route/component", "kind": "discovery"})
        edges.append({"source": cid, "target": tid, "label": "test", "kind": "test"})
        edges.append({"source": tid, "target": fid, "label": f.get("severity", ""), "kind": "finding"})
        if f.get("patch_status") in ("verified", "applied"):
            pid = f"patch-{i}"
            nodes.append({"id": pid, "label": "patch", "kind": "patch", "status": f.get("patch_status")})
            edges.append({"source": fid, "target": pid, "label": "fix", "kind": "patch"})
    return nodes + edges


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {
        "findings_total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0,
        "confirmed": 0, "fixed": 0, "verified": 0, "needs_review": 0,
    }
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        key = sev.lower()
        if key in counts:
            counts[key] += 1
        if f.get("provenance") in ("Confirmed", "Verified"):
            counts["confirmed"] += 1
        if f.get("status") == "fixed":
            counts["fixed"] += 1
        if f.get("patch_status") == "verified":
            counts["verified"] += 1
        if f.get("status") == "needs_review":
            counts["needs_review"] += 1
    return counts
