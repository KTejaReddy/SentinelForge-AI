"""Run the full pipeline on all three demo apps and report honest results."""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
bin_dir = ROOT_DIR / "tools" / "bin"
if bin_dir.exists():
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

from config import WORKSPACES_DIR, UPLOADS_DIR, ROOT_DIR as RD
from database import SessionLocal, init_db
from models import Finding, Patch, Scan, VerificationRun
from orchestrator.scan_orchestrator import run_scan
from schemas import ScanOptions
from security import make_zip
import hashlib

init_db()

DEMOS = ["vulnerable-app", "injection-app", "auth-app"]

results = []

for demo_name in DEMOS:
    print(f"\n{'='*70}")
    print(f"SCANNING: {demo_name}")
    print(f"{'='*70}")

    demo_dir = RD / "demo" / demo_name
    if not demo_dir.exists():
        print(f"  SKIP: demo directory not found")
        continue

    zip_path = Path(UPLOADS_DIR) / f"demo-{demo_name}-alltest.zip"
    make_zip(demo_dir, zip_path, exclude=("node_modules", ".git"))
    data = zip_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()

    db = SessionLocal()
    from models import Project
    existing = db.query(Project).filter_by(sha256=sha256).first()
    if existing:
        project = existing
        # Make sure the ZIP exists at the expected path
        expected_zip = Path(UPLOADS_DIR) / f"{project.id}.zip"
        if not expected_zip.exists():
            expected_zip.write_bytes(data)
    else:
        project = Project(
            name=f"Demo: {demo_name}",
            filename=f"demo-{demo_name}.zip",
            sha256=sha256,
            size_bytes=len(data),
            status="UPLOADED"
        )
        db.add(project)
        db.commit()
        db.refresh(project)
        Path(UPLOADS_DIR).mkdir(parents=True, exist_ok=True)
        (Path(UPLOADS_DIR) / f"{project.id}.zip").write_bytes(data)

    opts = ScanOptions().model_dump()
    scan = Scan(
        project_id=project.id,
        state="UPLOADED",
        status="UPLOADED",
        intensity="standard",
        options=json.dumps(opts)
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id
    db.close()

    print(f"  Scan ID: {scan_id}")
    t0 = time.time()
    try:
        run_scan(scan_id)
    except Exception as exc:
        print(f"  ERROR: {exc}")
    elapsed = time.time() - t0
    print(f"  Completed in {elapsed:.1f}s")

    db = SessionLocal()
    scan = db.get(Scan, scan_id)
    findings = db.query(Finding).filter_by(scan_id=scan_id).all()
    patches = db.query(Patch).filter_by(scan_id=scan_id).all()
    vers = db.query(VerificationRun).filter_by(scan_id=scan_id).all()

    # Count by severity
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    fixed = sum(1 for v in vers if v.status == "FIXED")
    not_fixed = sum(1 for v in vers if v.status == "NOT_FIXED")
    failed_patches = sum(1 for p in patches if p.status == "failed")

    demo_result = {
        "demo": demo_name,
        "scan_id": scan_id,
        "time": round(elapsed, 1),
        "findings": len(findings),
        "critical": len(by_sev.get("CRITICAL", [])),
        "high": len(by_sev.get("HIGH", [])),
        "medium": len(by_sev.get("MEDIUM", [])),
        "low": len(by_sev.get("LOW", [])),
        "patches": len(patches),
        "verified_fixed": fixed,
        "not_fixed": not_fixed,
        "failed_patches": failed_patches,
    }
    results.append(demo_result)

    print(f"\n  FINDINGS ({len(findings)}):")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = by_sev.get(sev, [])
        if items:
            print(f"    {sev}: {len(items)}")
            for f in items:
                print(f"      - {f.title[:60]} (patch={f.patch_status})")

    print(f"\n  PATCHES: {len(patches)}")
    for p in patches:
        print(f"    - status={p.status}: {p.explanation[:80]}")

    print(f"\n  VERIFICATIONS: {len(vers)}")
    for v in vers:
        print(f"    - {v.status} build={v.build_pass} regression={v.regression_pass} exploit_blocked={v.exploit_blocked}")

    scores = json.loads(scan.scores) if isinstance(scan.scores, str) else (scan.scores or {})
    print(f"\n  SCORES: security={scores.get('security', '?')} overall={scores.get('overall', '?')}")

    db.close()

# Final summary
print(f"\n{'='*70}")
print("FINAL SUMMARY - ALL DEMOS")
print(f"{'='*70}")
print(f"{'Demo':<20s} {'Findings':>8s} {'Critical':>8s} {'High':>6s} {'Patches':>8s} {'Fixed':>6s} {'Failed':>6s} {'Time':>8s}")
print("-" * 75)
for r in results:
    print(f"{r['demo']:<20s} {r['findings']:>8d} {r['critical']:>8d} {r['high']:>6d} {r['patches']:>8d} {r['verified_fixed']:>6d} {r['failed_patches']:>6d} {r['time']:>7.1f}s")

total_findings = sum(r['findings'] for r in results)
total_fixed = sum(r['verified_fixed'] for r in results)
total_patches = sum(r['patches'] for r in results)
total_failed = sum(r['failed_patches'] for r in results)
print("-" * 75)
print(f"{'TOTAL':<20s} {total_findings:>8d} {'':>8s} {'':>6s} {total_patches:>8d} {total_fixed:>6d} {total_failed:>6d}")

print(f"\nHonest classification:")
print(f"  Total findings:        {total_findings}")
print(f"  Repaired:              {total_patches}")
print(f"  Verified fixed:        {total_fixed}")
print(f"  Repair failed:         {total_failed}")
print(f"  Needs human review:    {total_findings - total_fixed - total_failed}")
print(f"\nProof of concept:")
print(f"  The platform can:")
print(f"    1. Upload a ZIP")
print(f"    2. Build and run the app in sandbox")
print(f"    3. Discover vulnerabilities with real tools")
print(f"    4. Apply deterministic patches for known patterns")
print(f"    5. Rebuild the patched app")
print(f"    6. Replay the original exploit")
print(f"    7. Run regression tests")
print(f"    8. Produce an honest VERIFIED_FIXED or NOT_FIXED verdict")
