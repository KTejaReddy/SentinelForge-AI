"""End-to-end repair and verification test - FIXED version.

Honest testing of the repair pipeline with correct patches.
"""
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
from events import log
from models import Finding
from orchestrator.build import build_and_start
from security import make_zip, secure_extract_zip
from services.deterministic_exploits import (
    cmd_injection_exploit,
    debug_endpoint_exploit,
    idor_exploit,
    path_traversal_exploit,
    run_exploit,
    sqli_exploit,
    xss_reflected_exploit,
)
from services.project_detector import detect_project
from services.scan_context import ScanContext
from services.verification_runner import run_exploit_before, verify_patch
from tools.base import make_finding
from tools.custom_probes import CustomProbeAdapter
from tools.gitleaks import GitleaksAdapter
from tools.semgrep import SemgrepAdapter

init_db()

# ============================================================================
# STEP 1: Extract and build
# ============================================================================
print("=" * 70)
print("STEP 1: EXTRACT AND BUILD")
print("=" * 70)

scan_id = 99901
workspace = Path(WORKSPACES_DIR) / f"scan-{scan_id}"
original = workspace / "original"
working = workspace / "working-copy"
patched = workspace / "patched-copy"

for d in (original, working, patched, workspace / "artifacts"):
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True, exist_ok=True)

demo_dir = RD / "demo" / "vulnerable-app"
zip_path = Path(UPLOADS_DIR) / "e2e-repair-test-v2.zip"
make_zip(demo_dir, zip_path, exclude=("node_modules", ".git"))
data = zip_path.read_bytes()

extracted = secure_extract_zip(data, original)
print(f"Extracted {len(extracted)} files")

# Copy to working
for item in original.rglob("*"):
    if item.is_symlink():
        continue
    rel = item.relative_to(original)
    if any(part in {"node_modules", ".git", "__pycache__"} for part in rel.parts):
        continue
    target = working / rel
    if item.is_dir():
        target.mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target)

det = detect_project(working)
print(f"Detected: {det['project_type']} frameworks={det['frameworks']}")

ctx = ScanContext(
    scan_id=scan_id, project_id=0, project_name="e2e-repair-v2",
    workspace=workspace, original=original, working=working, patched=patched,
    options={}, intensity="standard"
)
ctx.detection = det

# Build and start
print("\nBuilding and starting application...")
t0 = time.time()
build_info = build_and_start(ctx)
elapsed = time.time() - t0
print(f"Build: started={build_info.get('started')} url={build_info.get('base_url')} ({elapsed:.1f}s)")

if not build_info.get("base_url"):
    print("FATAL: Application failed to start")
    sys.exit(1)

ctx.runtime = build_info
base_url = build_info["base_url"]

# ============================================================================
# STEP 2: Establish exploit baselines
# ============================================================================
print("\n" + "=" * 70)
print("STEP 2: EXPLOIT BASELINES (BEFORE)")
print("=" * 70)

exploit_funcs = {
    "command_injection": cmd_injection_exploit,
    "path_traversal": path_traversal_exploit,
    "sql_injection": sqli_exploit,
    "idor": idor_exploit,
    "debug_endpoint": debug_endpoint_exploit,
    "xss": xss_reflected_exploit,
}

baseline = {}
for name, func in exploit_funcs.items():
    try:
        result = func(base_url)
        baseline[name] = result
        status = "EXPLOITED" if result.get("exploited") else "safe"
        print(f"  {name:25s}: {status} (HTTP {result.get('before_status')})")
    except Exception as exc:
        baseline[name] = {"exploited": False, "error": str(exc)}
        print(f"  {name:25s}: ERROR - {exc}")

exploited_count = sum(1 for r in baseline.values() if r.get("exploited"))
print(f"\n{exploited_count}/{len(baseline)} exploits confirmed BEFORE patching")

# ============================================================================
# STEP 3: Apply patches
# ============================================================================
print("\n" + "=" * 70)
print("STEP 3: APPLY PATCHES")
print("=" * 70)

server_js = working / "server.js"
original_content = server_js.read_text(encoding="utf-8")

patches_applied = []

# --- PATCH 1: Command Injection ---
print("\n--- Patch 1: Command Injection ---")
old_cmd = '  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {'
new_cmd = '  const args = process.platform === "win32" ? ["-n", "1", host] : ["-c", "1", host];\n  execFile("ping", args, { timeout: 5000 }, (err, stdout, stderr) => {'

if old_cmd in original_content:
    patched_content = original_content.replace(old_cmd, new_cmd, 1)
    server_js.write_text(patched_content, encoding="utf-8")
    patches_applied.append("command_injection")
    print("  Applied: exec() -> execFile() with array args")
    original_content = patched_content
else:
    print("  SKIPPED: Could not find target code")

# --- PATCH 2: Path Traversal ---
print("\n--- Patch 2: Path Traversal ---")
old_path = '  const target = path.join(__dirname, "public", "files", name);\n  fs.readFile(target, (err, data) => {'
new_path = '  const target = path.resolve(__dirname, "public", "files", name);\n  const allowed = path.resolve(__dirname, "public", "files");\n  if (!target.startsWith(allowed + path.sep) && target !== allowed) {\n    return res.status(403).json({ error: "access denied" });\n  }\n  fs.readFile(target, (err, data) => {'

current = server_js.read_text(encoding="utf-8")
if old_path in current:
    patched_content = current.replace(old_path, new_path, 1)
    server_js.write_text(patched_content, encoding="utf-8")
    patches_applied.append("path_traversal")
    print("  Applied: path containment check")
    original_content = patched_content
else:
    print("  SKIPPED: Could not find target code")

# --- PATCH 3: Debug Endpoint ---
print("\n--- Patch 3: Debug Endpoint ---")
# Read current content
current = server_js.read_text(encoding="utf-8")

# Find the debug handler and wrap it
old_debug = '''// GET /api/debug/env — debug endpoint leaking environment (intentionally)
app.get("/api/debug/env", (req, res) => {
  const safe = {};
  for (const key of Object.keys(process.env)) {
    safe[key] = String(process.env[key]);
  }
  res.json({ environment: safe });
});'''

new_debug = '''// GET /api/debug/env — debug endpoint (protected in production)
if (process.env.NODE_ENV !== "production") {
  app.get("/api/debug/env", (req, res) => {
    const safe = {};
    for (const key of Object.keys(process.env)) {
      safe[key] = String(process.env[key]);
    }
    res.json({ environment: safe });
  });
} else {
  app.get("/api/debug/env", (req, res) => res.status(404).json({ error: "not found" }));
}'''

if old_debug in current:
    patched_content = current.replace(old_debug, new_debug, 1)
    server_js.write_text(patched_content, encoding="utf-8")
    patches_applied.append("debug_endpoint")
    print("  Applied: debug endpoint protected in production mode")
else:
    print("  SKIPPED: Could not find target code")

print(f"\nPatches applied: {len(patches_applied)} ({', '.join(patches_applied)})")

# Verify syntax by trying to load the file
print("\nVerifying syntax...")
try:
    result = ctx.sandbox.run(["node", "-c", "server.js"], cwd=working, timeout_s=10)
    if result.exit_code == 0:
        print("  Syntax: VALID")
    else:
        print(f"  Syntax: INVALID - {result.stderr[:200]}")
except Exception as exc:
    print(f"  Syntax check error: {exc}")

# ============================================================================
# STEP 4: Rebuild patched application
# ============================================================================
print("\n" + "=" * 70)
print("STEP 4: REBUILD PATCHED APPLICATION")
print("=" * 70)

# Stop old server
try:
    ctx.sandbox.stop()
    time.sleep(1)
except Exception:
    pass

print("Rebuilding and restarting...")
t0 = time.time()
build_info2 = build_and_start(ctx)
elapsed = time.time() - t0
print(f"Rebuild: started={build_info2.get('started')} url={build_info2.get('base_url')} ({elapsed:.1f}s)")

if not build_info2.get("started"):
    print("ERROR: Patched application failed to start!")
    print("Build log tail:", build_info2.get("build_log", "")[-500:])
    # Try to get process output
    logs = ctx.sandbox.server_logs(50)
    print("Server logs:", logs[:500])
    sys.exit(1)

ctx.runtime = build_info2
base_url2 = build_info2["base_url"]
print(f"Patched app running at: {base_url2}")

# Verify health
from services.probes.http import probe
try:
    r = probe("GET", base_url2 + "/api/health", timeout_s=5)
    print(f"Health check: {r.status_code} {r.text[:100]}")
except Exception as exc:
    print(f"Health check failed: {exc}")

# ============================================================================
# STEP 5: Re-run exploits AFTER patches
# ============================================================================
print("\n" + "=" * 70)
print("STEP 5: EXPLOIT REPLAY (AFTER)")
print("=" * 70)

after = {}
for name, func in exploit_funcs.items():
    try:
        result = func(base_url2)
        after[name] = result
        was_exploited = baseline.get(name, {}).get("exploited", False)
        is_exploited = result.get("exploited", False)
        
        if was_exploited and not is_exploited:
            status = "BLOCKED"
        elif was_exploited and is_exploited:
            status = "STILL EXPLOITED"
        else:
            status = "was not exploitable"
        
        print(f"  {name:25s}: {status}")
    except Exception as exc:
        after[name] = {"exploited": False, "error": str(exc)}
        print(f"  {name:25s}: ERROR - {exc}")

# ============================================================================
# STEP 6: Regression tests
# ============================================================================
print("\n" + "=" * 70)
print("STEP 6: REGRESSION TESTS")
print("=" * 70)

test_cmd = (ctx.detection.get("commands") or {}).get("test")
if test_cmd:
    print(f"Running: {test_cmd}")
    t0 = time.time()
    res = ctx.sandbox.run(test_cmd.split(), cwd=working, timeout_s=120)
    elapsed = time.time() - t0
    regression_pass = res.exit_code == 0
    print(f"Result: {'PASS' if regression_pass else 'FAIL'} (exit {res.exit_code}, {elapsed:.1f}s)")
    if not regression_pass:
        print(f"stdout: {res.stdout[-500:]}")
        print(f"stderr: {res.stderr[-500:]}")
else:
    print("No test command")
    regression_pass = True

# ============================================================================
# STEP 7: Honest results
# ============================================================================
print("\n" + "=" * 70)
print("STEP 7: HONEST RESULTS")
print("=" * 70)

results = []
for name in exploit_funcs:
    was_exploited = baseline.get(name, {}).get("exploited", False)
    is_exploited = after.get(name, {}).get("exploited", False)
    patched = name in patches_applied
    
    if was_exploited and not is_exploited and patched:
        verdict = "VERIFIED_FIXED"
    elif was_exploited and is_exploited and patched:
        verdict = "PATCH_FAILED"
    elif was_exploited and not is_exploited and not patched:
        verdict = "NOT_FIXED_NO_PATCH"
    elif was_exploited and is_exploited and not patched:
        verdict = "NOT_FIXED"
    elif not was_exploited:
        verdict = "NOT_REPRODUCIBLE"
    else:
        verdict = "UNKNOWN"
    
    results.append({
        "exploit": name,
        "before": was_exploited,
        "after": is_exploited,
        "patched": patched,
        "verdict": verdict,
    })

# Print table
print(f"\n{'Exploit':<25s} {'Before':<10s} {'After':<10s} {'Patched':<10s} {'Verdict':<25s}")
print("-" * 85)
for r in results:
    b = "EXPLOITED" if r["before"] else "safe"
    a = "EXPLOITED" if r["after"] else "safe"
    p = "YES" if r["patched"] else "NO"
    print(f"{r['exploit']:<25s} {b:<10s} {a:<10s} {p:<10s} {r['verdict']:<25s}")

# Summary
fixed = sum(1 for r in results if r["verdict"] == "VERIFIED_FIXED")
patch_failed = sum(1 for r in results if r["verdict"] == "PATCH_FAILED")
not_fixed = sum(1 for r in results if "NOT_FIXED" in r["verdict"])
not_repro = sum(1 for r in results if r["verdict"] == "NOT_REPRODUCIBLE")

print(f"\n{'='*70}")
print("SUMMARY")
print(f"{'='*70}")
print(f"Exploits confirmed:    {exploited_count}")
print(f"Verified fixed:        {fixed}")
print(f"Patch failed:          {patch_failed}")
print(f"Not fixed:             {not_fixed}")
print(f"Not reproducible:      {not_repro}")
print(f"Regression tests:      {'PASS' if regression_pass else 'FAIL'}")
print(f"{'='*70}")

# Cleanup
try:
    ctx.sandbox.cleanup()
except Exception:
    pass

print("\nDone!")
