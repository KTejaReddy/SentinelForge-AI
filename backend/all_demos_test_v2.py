"""Test all 3 demo applications end-to-end."""
import sys
import os
import time
import zipfile
from pathlib import Path

sys.path.insert(0, '.')

from config import UPLOADS_DIR, WORKSPACES_DIR
from services.project_detector import detect_project
from orchestrator.scan_orchestrator import run_scan
from database import SessionLocal, init_db
from models import Project, Scan, Finding, Patch, VerificationRun

# Initialize database
init_db()

def create_demo_zip(demo_name: str) -> Path:
    """Create a ZIP file for a demo application."""
    demo_dir = Path('..') / 'demo' / demo_name
    zip_path = UPLOADS_DIR / f'demo-{demo_name}.zip'
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in demo_dir.rglob('*'):
            if f.is_file() and 'node_modules' not in str(f):
                zf.write(f, f.relative_to(demo_dir.parent))
    return zip_path

def run_demo_scan(demo_name: str) -> dict:
    """Run a full scan on a demo application."""
    print(f"\n{'='*60}")
    print(f"Scanning {demo_name}")
    print(f"{'='*60}")
    
    # Create ZIP
    zip_path = create_demo_zip(demo_name)
    print(f"Created ZIP: {zip_path.stat().st_size} bytes")
    
    # Create project
    db = SessionLocal()
    try:
        project = Project(
            name=demo_name,
            filename=zip_path.name,
            sha256=str(zip_path.stat().st_size),  # simplified
            size_bytes=zip_path.stat().st_size,
            status="UPLOADED"
        )
        db.add(project)
        db.commit()
        db.refresh(project)
        
        # Create scan
        scan = Scan(
            project_id=project.id,
            status="UPLOADED",
            intensity="standard"
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
        
        # Count by status
        fixed_count = sum(1 for f in findings if f.status == "fixed")
        verified_count = sum(1 for f in findings if f.patch_status == "verified")
        needs_review = sum(1 for f in findings if f.status == "needs_review")
        
        # Count by severity
        severity_counts = {}
        for f in findings:
            sev = f.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        result = {
            "demo": demo_name,
            "findings": len(findings),
            "fixed": fixed_count,
            "verified": verified_count,
            "needs_review": needs_review,
            "patches": len(patches),
            "verifications": len(verifications),
            "severity": severity_counts,
            "elapsed": round(elapsed, 1),
        }
        
        print(f"\nResults for {demo_name}:")
        print(f"  Findings: {len(findings)}")
        print(f"  Fixed: {fixed_count}")
        print(f"  Verified: {verified_count}")
        print(f"  Needs review: {needs_review}")
        print(f"  Patches: {len(patches)}")
        print(f"  Severity: {severity_counts}")
        print(f"  Time: {elapsed:.1f}s")
        
        # Print details
        print(f"\n  Findings:")
        for f in findings:
            tool = getattr(f, 'repair_tool', '') or ''
            print(f"    [{f.severity}] {f.title[:50]}")
            print(f"      status={f.status}, patch_status={f.patch_status}, repair_tool={tool}")
        
        print(f"\n  Patches:")
        for p in patches:
            print(f"    ID={p.id}: {p.tool_source} ({p.repair_type})")
            print(f"      {p.explanation[:80]}")
        
        print(f"\n  Verifications:")
        for v in verifications:
            print(f"    status={v.status}, exploit_blocked={v.exploit_blocked}")
        
        return result
    finally:
        db.close()


if __name__ == "__main__":
    # Run all demos
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
    total_findings = sum(r.get("findings", 0) for r in results)
    total_fixed = sum(r.get("fixed", 0) for r in results)
    total_verified = sum(r.get("verified", 0) for r in results)
    
    print(f"Total findings: {total_findings}")
    print(f"Total fixed: {total_fixed}")
    print(f"Total verified: {total_verified}")
    
    for r in results:
        if "error" in r:
            print(f"  {r['demo']}: ERROR - {r['error']}")
        else:
            print(f"  {r['demo']}: {r['findings']} findings, {r['fixed']} fixed, {r['verified']} verified")
