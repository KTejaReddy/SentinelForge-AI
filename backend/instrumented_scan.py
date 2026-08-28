"""Instrumented scan to find where it hangs."""
import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
bin_dir = ROOT_DIR / "tools" / "bin"
if bin_dir.exists():
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

# Monkey-patch the _step function to add timing
import orchestrator.scan_orchestrator as orch

_original_step = orch._step

def _timed_step(scan_id, key, name, fn, ctx):
    t0 = time.time()
    sys.stdout.flush()
    print(f"[STEP START] {name} (key={key})", flush=True)
    try:
        result = _original_step(scan_id, key, name, fn, ctx)
        elapsed = time.time() - t0
        print(f"[STEP DONE]  {name} ({elapsed:.1f}s)", flush=True)
        return result
    except Exception as e:
        elapsed = time.time() - t0
        print(f"[STEP FAIL]  {name} ({elapsed:.1f}s): {e}", flush=True)
        raise

orch._step = _timed_step

from orchestrator.scan_orchestrator import run_scan
from database import SessionLocal, init_db
from models import Scan, Project
from config import UPLOADS_DIR
from security import make_zip
from schemas import ScanOptions
import hashlib, json

init_db()

demo_dir = ROOT_DIR / "demo" / "vulnerable-app"
zip_path = Path(UPLOADS_DIR) / "e2e-instrumented.zip"
make_zip(demo_dir, zip_path, exclude=("node_modules", ".git"))
data = zip_path.read_bytes()
sha256 = hashlib.sha256(data).hexdigest()

db = SessionLocal()
existing = db.query(Project).filter_by(sha256=sha256).first()
if existing:
    project = existing
else:
    project = Project(name="Instrumented Test", filename="vulnerable-app.zip", sha256=sha256, size_bytes=len(data), status="UPLOADED")
    db.add(project)
    db.commit()
    db.refresh(project)

opts = ScanOptions().model_dump()
scan = Scan(project_id=project.id, state="UPLOADED", status="UPLOADED", intensity="standard", options=json.dumps(opts))
db.add(scan)
db.commit()
db.refresh(scan)
scan_id = scan.id
db.close()

print(f"\n=== Scan {scan_id} starting ===", flush=True)
t0 = time.time()
run_scan(scan_id)
print(f"\n=== Scan {scan_id} completed in {time.time()-t0:.1f}s ===", flush=True)

from models import Finding
db = SessionLocal()
findings = db.query(Finding).filter_by(scan_id=scan_id).all()
print(f"Findings: {len(findings)}")
for f in findings:
    print(f"  [{f.severity}] {f.title[:80]} ({f.source})")
db.close()
