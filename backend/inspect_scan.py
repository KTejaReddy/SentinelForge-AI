"""Inspect scan #15 repair/verification details."""
import json
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
bin_dir = ROOT_DIR / "tools" / "bin"
if bin_dir.exists():
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

from database import SessionLocal
from models import Scan, Finding, Patch, VerificationRun, Evidence, AgentRun

db = SessionLocal()

# Scan details
scan = db.get(Scan, 15)
if not scan:
    print("Scan 15 not found")
    sys.exit(1)

print(f"=== SCAN {scan.id}: {scan.state} ===")
summary = json.loads(scan.summary) if isinstance(scan.summary, str) else (scan.summary or {})
scores = json.loads(scan.scores) if isinstance(scan.scores, str) else (scan.scores or {})
print(f"Scores: {json.dumps(scores, indent=2)}")
print(f"Limitations: {summary.get('limitations', [])}")

# All findings
print(f"\n=== FINDINGS ({db.query(Finding).filter_by(scan_id=15).count()}) ===")
findings = db.query(Finding).filter_by(scan_id=15).all()
for f in findings:
    print(f"\n--- Finding {f.id}: [{f.severity}] {f.title} ---")
    print(f"  category: {f.category}")
    print(f"  source: {f.source}")
    print(f"  status: {f.status}")
    print(f"  patch_status: {f.patch_status}")
    print(f"  provenance: {f.provenance}")
    print(f"  confidence: {f.confidence}")
    print(f"  affected_file: {f.affected_file}:{f.line_start}")
    rep = json.loads(f.reproduction) if isinstance(f.reproduction, str) else f.reproduction
    print(f"  reproduction: {json.dumps(rep, indent=4)[:300]}")
    if f.root_cause:
        print(f"  root_cause: {f.root_cause[:200]}")
    if f.recommended_fix:
        print(f"  recommended_fix: {f.recommended_fix[:200]}")

# Patches
patches = db.query(Patch).filter_by(scan_id=15).all()
print(f"\n=== PATCHES ({len(patches)}) ===")
for p in patches:
    print(f"\n--- Patch {p.id}: status={p.status} ---")
    print(f"  finding_id: {p.finding_id}")
    print(f"  diff: {p.diff[:300]}")
    print(f"  explanation: {p.explanation[:200]}")
    files = json.loads(p.files) if isinstance(p.files, str) else (p.files or {})
    for fname, content in files.items():
        print(f"  file: {fname}")
        if isinstance(content, dict):
            print(f"    before: {content.get('before', '')[:100]}")
            print(f"    after: {content.get('after', '')[:100]}")

# Verifications
vers = db.query(VerificationRun).filter_by(scan_id=15).all()
print(f"\n=== VERIFICATIONS ({len(vers)}) ===")
for v in vers:
    print(f"\n--- Verification {v.id}: status={v.status} ---")
    print(f"  patch_id: {v.patch_id}")
    print(f"  finding_id: {v.finding_id}")
    print(f"  build_pass: {v.build_pass}")
    print(f"  regression_pass: {v.regression_pass}")
    print(f"  exploit_blocked: {v.exploit_blocked}")
    details = json.loads(v.details) if isinstance(v.details, str) else (v.details or {})
    print(f"  details: {json.dumps(details, indent=2)[:400]}")

# Agent runs
agents = db.query(AgentRun).filter_by(scan_id=15).all()
print(f"\n=== AGENT RUNS ({len(agents)}) ===")
for a in agents:
    print(f"  {a.agent:25s} {a.status:10s} {a.summary[:100]}")

# Evidence
evidence = db.query(Evidence).all()
print(f"\n=== EVIDENCE ROWS ({len(evidence)}) ===")
for e in evidence:
    print(f"  finding_id={e.finding_id} tool={e.tool} target={e.target[:60]}")

# Tool runs
from models import ToolRun
tools = db.query(ToolRun).filter_by(scan_id=15).all()
print(f"\n=== TOOL RUNS ({len(tools)}) ===")
for t in tools:
    print(f"  {t.tool:25s} {t.status:12s} {t.duration_ms}ms")

db.close()
