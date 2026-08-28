"""End-to-end smoke test: demo project → full scan → reports.

Usage:  python scripts/smoke_scan.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from config import UPLOADS_DIR  # noqa: E402
from database import SessionLocal, init_db  # noqa: E402
from models import Finding, Project, Scan  # noqa: E402
from security import make_zip  # noqa: E402


def main() -> int:
    init_db()
    demo_dir = ROOT / "demo" / "vulnerable-app"
    zip_path = Path(UPLOADS_DIR) / "smoke-demo.zip"
    make_zip(demo_dir, zip_path, exclude=("node_modules",))
    data = zip_path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()

    db = SessionLocal()
    try:
        project = db.query(Project).filter_by(sha256=sha).first()
        if not project:
            project = Project(name="smoke-demo", filename="smoke-demo.zip", sha256=sha, size_bytes=len(data), status="UPLOADED")
            db.add(project)
            db.commit()
            db.refresh(project)
            (Path(UPLOADS_DIR) / f"{project.id}.zip").write_bytes(data)
        opts = {
            "security_testing": True, "bug_hunting": True, "static_analysis": True,
            "dependency_analysis": True, "secrets_detection": True, "dynamic_testing": True,
            "browser_testing": True, "fuzzing": True, "automatic_repair": True, "verification": True,
            "intensity": "standard",
        }
        scan = Scan(project_id=project.id, state="UPLOADED", status="UPLOADED", intensity="standard", options=json.dumps(opts))
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    print(f"Starting scan {scan_id} on project {project.id} ...")
    from orchestrator.scan_orchestrator import run_scan

    run_scan(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        print("\n===== SCAN RESULT =====")
        print("status:", scan.status, "| state:", scan.state)
        print("scores:", scan.scores)
        print(f"findings: {len(findings)}")
        for f in findings:
            print(f"  [{f.severity}] {f.title} | {f.affected_file}:{f.line_start} | patch={f.patch_status} | status={f.status}")
        summary = json.loads(scan.summary) if isinstance(scan.summary, str) else (scan.summary or {})
        print("\nlimitations:")
        for lim in summary.get("limitations", []):
            print("  -", lim)
        print("\nattack graph nodes+edges:", len(summary.get("attack_graph", [])))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
