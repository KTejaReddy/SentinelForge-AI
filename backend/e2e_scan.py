"""End-to-end scan test: extract vulnerable-app, build, scan, verify."""
import os
import sys
import json
import time
import shutil
from pathlib import Path

# Ensure tools/bin is on PATH before any tool detection
ROOT_DIR = Path(__file__).resolve().parent.parent
bin_dir = ROOT_DIR / "tools" / "bin"
if bin_dir.exists():
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

from config import WORKSPACES_DIR, UPLOADS_DIR, ROOT_DIR as RD
from database import SessionLocal, init_db
from models import Scan, Project, Finding, ScanStep, ToolRun
from orchestrator.scan_orchestrator import run_scan
from security import make_zip, secure_extract_zip
from schemas import ScanOptions
from services.project_detector import detect_project

init_db()

# Create project from demo
demo_dir = RD / "demo" / "vulnerable-app"
zip_path = Path(UPLOADS_DIR) / "e2e-test-vulnerable.zip"
make_zip(demo_dir, zip_path, exclude=("node_modules", ".git"))
data = zip_path.read_bytes()
import hashlib
sha256 = hashlib.sha256(data).hexdigest()

db = SessionLocal()
existing = db.query(Project).filter_by(sha256=sha256).first()
if existing:
    project = existing
    print(f"Using existing project: {project.name} (id={project.id})")
else:
    project = Project(
        name="E2E Vulnerable App",
        filename="vulnerable-app.zip",
        sha256=sha256,
        size_bytes=len(data),
        status="UPLOADED",
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    print(f"Created project: {project.name} (id={project.id})")

opts = ScanOptions().model_dump()
scan = Scan(
    project_id=project.id,
    state="UPLOADED",
    status="UPLOADED",
    intensity="standard",
    options=json.dumps(opts),
)
db.add(scan)
db.commit()
db.refresh(scan)
scan_id = scan.id
db.close()

print(f"\n=== Starting scan {scan_id} ===")
sys.stdout.flush()

t0 = time.time()
run_scan(scan_id)
elapsed = time.time() - t0

print(f"\n=== Scan {scan_id} complete in {elapsed:.1f}s ===")
sys.stdout.flush()

# Print results
db = SessionLocal()
scan = db.get(Scan, scan_id)
print(f"Status: {scan.state}")
print(f"Progress: {scan.progress}")

findings = db.query(Finding).filter_by(scan_id=scan_id).all()
print(f"\nFindings: {len(findings)}")
for f in findings:
    print(f"  [{f.severity:8s}] {f.title[:80]}")
    print(f"             source={f.source}, category={f.category}, provenance={f.provenance}")
    if f.patch_status not in ("none", ""):
        print(f"             patch_status={f.patch_status}")

steps = db.query(ScanStep).filter_by(scan_id=scan_id).all()
print(f"\nSteps ({len(steps)}):")
for s in steps:
    dur = ""
    if s.started_at and s.finished_at:
        dur = f" ({(s.finished_at - s.started_at).total_seconds():.1f}s)"
    print(f"  {s.name:35s} -> {s.status}{dur}")

tool_runs = db.query(ToolRun).filter_by(scan_id=scan_id).all()
print(f"\nTool Runs ({len(tool_runs)}):")
for t in tool_runs:
    print(f"  {t.tool:25s} -> {t.status} ({t.duration_ms}ms)")

if scan.summary:
    summary = json.loads(scan.summary) if isinstance(scan.summary, str) else scan.summary
    print(f"\nSummary keys: {list(summary.keys())}")

if scan.scores:
    scores = json.loads(scan.scores) if isinstance(scan.scores, str) else scan.scores
    print(f"Scores: {scores}")

db.close()
