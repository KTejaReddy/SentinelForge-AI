"""Persistence helpers - findings, patches, verifications, reports."""
from __future__ import annotations

import json
from typing import Any

from database import SessionLocal
from models import Evidence, Finding, Patch, Report, VerificationRun


def save_findings(scan_id: int, findings: list[dict[str, Any]]) -> list[int]:
    """Insert/refresh findings for a scan. Returns DB finding ids (same order)."""
    ids: list[int] = []
    db = SessionLocal()
    try:
        existing = {f.dedup_key: f for f in db.query(Finding).filter_by(scan_id=scan_id).all()}
        for f in findings:
            key = f.get("dedup_key") or f.get("title", "")[:80]
            row = existing.get(key)
            if row is None:
                row = Finding(scan_id=scan_id, dedup_key=key)
                db.add(row)
            row.title = f.get("title", "")[:250]
            row.category = f.get("category", "other")[:60]
            row.severity = f.get("severity", "MEDIUM")[:16]
            row.confidence = float(f.get("confidence", 0.5))
            row.status = f.get("status", "open")[:30]
            row.source = f.get("source", "")[:60]
            row.affected_component = f.get("affected_component", "")[:250]
            row.affected_file = f.get("affected_file", "")[:1000]
            row.line_start = f.get("line_start")
            row.line_end = f.get("line_end")
            row.description = f.get("description", "")[:8000]
            row.why_it_matters = f.get("why_it_matters", "")[:4000]
            row.evidence = json.dumps(f.get("evidence", {}))
            row.reproduction = json.dumps(f.get("reproduction", {}))
            row.root_cause = f.get("root_cause", "")[:8000]
            row.ai_explanation = f.get("ai_explanation", "")[:8000]
            row.recommended_fix = f.get("recommended_fix", "")[:8000]
            row.patch_status = f.get("patch_status", "none")[:30]
            row.provenance = f.get("provenance", "Observed")[:30]
            db.flush()
            ids.append(row.id)
            # evidence rows
            for erow in db.query(Evidence).filter_by(finding_id=row.id).all():
                db.delete(erow)
            evidence = f.get("evidence", {}) or {}
            db.add(Evidence(
                finding_id=row.id,
                tool=evidence.get("tool", f.get("source", ""))[:60],
                target=evidence.get("target", "")[:1000],
                request=str(evidence.get("request", ""))[:8000],
                response=str(evidence.get("response", ""))[:8000],
                logs=str(evidence.get("logs", ""))[:8000],
                screenshot=evidence.get("screenshot", "")[:1000],
                source_file=f.get("affected_file", "")[:1000],
                source_line=f.get("line_start"),
                reproduction_steps=json.dumps(f.get("reproduction", {}))[:8000],
            ))
        db.commit()
    finally:
        db.close()
    return ids


def update_finding(finding_id: int, **fields: Any) -> None:
    db = SessionLocal()
    try:
        row = db.get(Finding, finding_id)
        if row:
            for k, v in fields.items():
                if hasattr(row, k):
                    if isinstance(v, (dict, list)):
                        v = json.dumps(v)
                    setattr(row, k, v)
            db.commit()
    finally:
        db.close()


def add_patch(scan_id: int, finding_id: int | None, diff: str, files: dict, explanation: str, status: str = "applied", tool_source: str = "", repair_type: str = "") -> int:
    db = SessionLocal()
    try:
        row = Patch(scan_id=scan_id, finding_id=finding_id, diff=diff[:200_000], files=json.dumps(files), explanation=explanation[:8000], status=status, tool_source=tool_source[:64], repair_type=repair_type[:64])
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


def add_verification(scan_id: int, patch_id: int | None, finding_id: int | None, status: str, build_pass: bool, regression_pass: bool, exploit_blocked: bool, details: dict) -> int:
    db = SessionLocal()
    try:
        row = VerificationRun(scan_id=scan_id, patch_id=patch_id, finding_id=finding_id, status=status, build_pass=build_pass, regression_pass=regression_pass, exploit_blocked=exploit_blocked, details=json.dumps(details))
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


def add_report(scan_id: int, report_type: str, path: str, fmt: str = "md") -> int:
    db = SessionLocal()
    try:
        row = Report(scan_id=scan_id, report_type=report_type, path=path, format=fmt)
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


def get_finding_by_dedup(scan_id: int, dedup_key: str) -> Finding | None:
    db = SessionLocal()
    try:
        return db.query(Finding).filter_by(scan_id=scan_id, dedup_key=dedup_key).first()
    finally:
        db.close()
