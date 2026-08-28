"""Run all 3 demos with Docker sandbox."""
import sys
import os
import time
import zipfile
from pathlib import Path

sys.path.insert(0, '.')

# Ensure tool dirs are on PATH before any tool detection
from config import ROOT_DIR
import os as _os
_existing = _os.environ.get('PATH', '')
_tool_dir = str(ROOT_DIR / 'tools' / 'bin')
if _tool_dir not in _existing:
    _os.environ['PATH'] = _tool_dir + _os.pathsep + _existing

from config import UPLOADS_DIR, WORKSPACES_DIR
from orchestrator.scan_orchestrator import run_scan
from database import SessionLocal, init_db
from models import Project, Scan, Finding, Patch, VerificationRun
from security import make_zip

# Initialize database
init_db()

ROOT_DIR = Path(__file__).resolve().parent.parent

def run_demo_scan(demo_name: str) -> dict:
    """Run a full scan on a demo application."""
    print(f"\n{'='*60}")
    print(f"Scanning {demo_name}")
    print(f"{'='*60}")
    
    # Create project first (to get the ID for the ZIP filename)
    import hashlib
    db = SessionLocal()
    try:
        # Create a temporary ZIP to compute sha256
        demo_dir = ROOT_DIR / 'demo' / demo_name
        tmp_zip = Path(UPLOADS_DIR) / f'tmp-{demo_name}.zip'
        make_zip(demo_dir, tmp_zip, exclude=('node_modules', '.git'))
        data = tmp_zip.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        
        existing = db.query(Project).filter_by(sha256=sha256).first()
        if existing:
            project = existing
        else:
            project = Project(
                name=demo_name,
                filename=f'{demo_name}.zip',
                sha256=sha256,
                size_bytes=len(data),
                status='UPLOADED'
            )
            db.add(project)
            db.commit()
            db.refresh(project)
        
        # Move the temporary ZIP to the correct name the orchestrator expects: {project.id}.zip
        zip_path = Path(UPLOADS_DIR) / f'{project.id}.zip'
        if zip_path.exists():
            zip_path.unlink()
        tmp_zip.rename(zip_path)
        
        scan = Scan(
            project_id=project.id,
            state='UPLOADED',
            status='UPLOADED',
            intensity='standard'
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()
    
    # Run scan
    start_time = time.time()
    try:
        run_scan(scan_id)
    except Exception as e:
        print(f"Scan failed: {e}")
        return {"error": str(e)}
    elapsed = time.time() - start_time
    
    # Collect results
    db = SessionLocal()
    try:
        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        patches = db.query(Patch).filter_by(scan_id=scan_id).all()
        verifications = db.query(VerificationRun).filter_by(scan_id=scan_id).all()
        
        fixed = sum(1 for f in findings if f.status == 'fixed')
        verified = sum(1 for f in findings if f.patch_status == 'verified')
        
        severity_counts = {}
        for f in findings:
            sev = f.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        result = {
            "demo": demo_name,
            "scan_id": scan_id,
            "findings": len(findings),
            "fixed": fixed,
            "verified": verified,
            "patches": len(patches),
            "verifications": len(verifications),
            "severity": severity_counts,
            "elapsed": round(elapsed, 1),
        }
        
        print(f"\nResults for {demo_name}:")
        print(f"  Scan ID: {scan_id}")
        print(f"  Findings: {len(findings)}")
        print(f"  Fixed: {fixed}")
        print(f"  Verified: {verified}")
        print(f"  Patches: {len(patches)}")
        print(f"  Severity: {severity_counts}")
        print(f"  Time: {elapsed:.1f}s")
        
        print(f"\n  Findings:")
        for f in findings:
            print(f"    [{f.severity}] {f.title[:60]}")
            print(f"      status={f.status}, patch_status={f.patch_status}")
        
        if patches:
            print(f"\n  Patches:")
            for p in patches:
                print(f"    ID={p.id}: {p.tool_source} ({p.repair_type})")
                print(f"      {p.explanation[:80]}")
        
        if verifications:
            print(f"\n  Verifications:")
            for v in verifications:
                print(f"    status={v.status}, exploit_blocked={v.exploit_blocked}")
        
        return result
    finally:
        db.close()


if __name__ == "__main__":
    demos = ["vulnerable-app", "injection-app", "auth-app"]
    results = []
    
    for demo in demos:
        try:
            result = run_demo_scan(demo)
            results.append(result)
        except Exception as e:
            print(f"Failed to scan {demo}: {e}")
            results.append({"demo": demo, "error": str(e)})
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    
    for r in results:
        if "error" in r:
            print(f"  {r['demo']}: ERROR - {r['error']}")
        else:
            print(f"  {r['demo']}: {r['findings']} findings, {r['fixed']} fixed, {r['verified']} verified")
