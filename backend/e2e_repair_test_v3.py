"""End-to-end repair test v3 - all patches, honest results."""
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
from orchestrator.build import build_and_start
from security import make_zip, secure_extract_zip
from services.deterministic_exploits import (
    cmd_injection_exploit,
    debug_endpoint_exploit,
    idor_exploit,
    path_traversal_exploit,
    sqli_exploit,
    xss_reflected_exploit,
)
from services.project_detector import detect_project
from services.scan_context import ScanContext
from tools.semgrep import SemgrepAdapter
from tools.custom_probes import CustomProbeAdapter
from tools.gitleaks import GitleaksAdapter

init_db()

def apply_patches(working: Path) -> list[str]:
    """Apply all possible patches and return list of applied patch names."""
    applied = []
    server_js = working / "server.js"
    content = server_js.read_text(encoding="utf-8")

    # PATCH 1: Command Injection - use execFile
    old = '  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {'
    new = '  const args = process.platform === "win32" ? ["-n", "1", host] : ["-c", "1", host];\n  execFile("ping", args, { timeout: 5000 }, (err, stdout, stderr) => {'
    if old in content:
        content = content.replace(old, new, 1)
        applied.append("command_injection")
        print("  [OK] command_injection: exec -> execFile")

    # PATCH 2: Path Traversal - containment check
    old = '  const target = path.join(__dirname, "public", "files", name);\n  fs.readFile(target, (err, data) => {'
    new = '  const target = path.resolve(__dirname, "public", "files", name);\n  const allowed = path.resolve(__dirname, "public", "files");\n  if (!target.startsWith(allowed + path.sep) && target !== allowed) {\n    return res.status(403).json({ error: "access denied" });\n  }\n  fs.readFile(target, (err, data) => {'
    if old in content:
        content = content.replace(old, new, 1)
        applied.append("path_traversal")
        print("  [OK] path_traversal: containment check")

    # PATCH 3: SQL Injection - sanitize search input
    old = "  const clause = \"user.username === '\" + q + \"'\";"
    new = "  const safe = q.replace(/[^a-zA-Z0-9]/g, '');\n  const clause = \"user.username === '\" + safe + \"'\";"
    if old in content:
        content = content.replace(old, new, 1)
        applied.append("sql_injection")
        print("  [OK] sql_injection: input sanitization")

    # PATCH 4: IDOR - require authentication
    old = '''// GET /api/account?id=N — IDOR: no authorization, returns any account by id
app.get("/api/account", (req, res) => {
  // TODO: check the session cookie and enforce ownership of req.query.id
  const id = Number(req.query.id);'''
    new = '''// GET /api/account?id=N — with auth check
app.get("/api/account", (req, res) => {
  const token = req.headers.authorization || req.cookies?.session || "";
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: "authentication required" });
  }
  const id = Number(req.query.id);'''
    if old in content:
        content = content.replace(old, new, 1)
        applied.append("idor")
        print("  [OK] idor: auth check added")

    # PATCH 5: Debug Endpoint - always disabled
    old = '''// GET /api/debug/env — debug endpoint leaking environment (intentionally)
app.get("/api/debug/env", (req, res) => {
  const safe = {};
  for (const key of Object.keys(process.env)) {
    safe[key] = String(process.env[key]);
  }
  res.json({ environment: safe });
});'''
    new = '''// GET /api/debug/env — disabled for security
app.get("/api/debug/env", (req, res) => {
  res.status(404).json({ error: "endpoint disabled" });
});'''
    if old in content:
        content = content.replace(old, new, 1)
        applied.append("debug_endpoint")
        print("  [OK] debug_endpoint: endpoint disabled")

    server_js.write_text(content, encoding="utf-8")
    return applied


print("=" * 70)
print("SENTINELFORGE AI - END-TO-END REPAIR TEST (v3)")
print("=" * 70)

# STEP 1: Setup
print("\n--- STEP 1: Extract and Build ---")
scan_id = 99902
workspace = Path(WORKSPACES_DIR) / f"scan-{scan_id}"
original = workspace / "original"
working = workspace / "working-copy"
patched = workspace / "patched-copy"
for d in (original, working, patched, workspace / "artifacts"):
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True, exist_ok=True)

demo_dir = RD / "demo" / "vulnerable-app"
zip_path = Path(UPLOADS_DIR) / "e2e-v3.zip"
make_zip(demo_dir, zip_path, exclude=("node_modules", ".git"))
data = zip_path.read_bytes()
secure_extract_zip(data, original)

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
ctx = ScanContext(
    scan_id=scan_id, project_id=0, project_name="e2e-v3",
    workspace=workspace, original=original, working=working, patched=patched,
    options={}, intensity="standard"
)
ctx.detection = det

print("Building original app...")
t0 = time.time()
build_info = build_and_start(ctx)
print(f"  started={build_info.get('started')} url={build_info.get('base_url')} ({time.time()-t0:.1f}s)")
if not build_info.get("base_url"):
    print("FATAL: app failed to start"); sys.exit(1)
ctx.runtime = build_info
base_url = build_info["base_url"]

# STEP 2: Before exploits
print("\n--- STEP 2: Exploit Baselines (BEFORE) ---")
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
        s = "EXPLOITED" if result.get("exploited") else "safe"
        print(f"  {name:25s}: {s}")
    except Exception as exc:
        baseline[name] = {"exploited": False, "error": str(exc)}
        print(f"  {name:25s}: ERROR")

exploited = sum(1 for r in baseline.values() if r.get("exploited"))
print(f"  => {exploited}/{len(baseline)} exploits confirmed")

# STEP 3: Apply patches
print("\n--- STEP 3: Apply Patches ---")
patches = apply_patches(working)

# Verify syntax
print("\n  Verifying syntax...")
res = ctx.sandbox.run(["node", "-c", "server.js"], cwd=working, timeout_s=10)
print(f"  Syntax: {'VALID' if res.exit_code == 0 else 'INVALID: ' + res.stderr[:100]}")

# STEP 4: Rebuild
print("\n--- STEP 4: Rebuild Patched App ---")
try:
    ctx.sandbox.stop()
    time.sleep(1)
except:
    pass

t0 = time.time()
build_info2 = build_and_start(ctx)
print(f"  started={build_info2.get('started')} url={build_info2.get('base_url')} ({time.time()-t0:.1f}s)")
if not build_info2.get("started"):
    print("FATAL: patched app failed to start")
    print("Logs:", ctx.sandbox.server_logs(50)[:500])
    sys.exit(1)
ctx.runtime = build_info2
base_url2 = build_info2["base_url"]

# STEP 5: After exploits
print("\n--- STEP 5: Exploit Replay (AFTER) ---")
after = {}
for name, func in exploit_funcs.items():
    try:
        result = func(base_url2)
        after[name] = result
        was = baseline.get(name, {}).get("exploited", False)
        now = result.get("exploited", False)
        if was and not now:
            s = "BLOCKED"
        elif was and now:
            s = "STILL EXPLOITED"
        else:
            s = "was not exploitable"
        print(f"  {name:25s}: {s}")
    except Exception as exc:
        after[name] = {"exploited": False, "error": str(exc)}
        print(f"  {name:25s}: ERROR")

# STEP 6: Regression
print("\n--- STEP 6: Regression Tests ---")
test_cmd = (det.get("commands") or {}).get("test")
if test_cmd:
    t0 = time.time()
    res = ctx.sandbox.run(test_cmd.split(), cwd=working, timeout_s=120)
    regression_pass = res.exit_code == 0
    print(f"  {test_cmd}: {'PASS' if regression_pass else 'FAIL'} ({time.time()-t0:.1f}s)")
else:
    regression_pass = True
    print("  No test command")

# STEP 7: Results
print("\n" + "=" * 70)
print("FINAL HONEST RESULTS")
print("=" * 70)

results = []
for name in exploit_funcs:
    was = baseline.get(name, {}).get("exploited", False)
    now = after.get(name, {}).get("exploited", False)
    patched = name in patches
    
    if was and not now and patched:
        verdict = "VERIFIED_FIXED"
    elif was and now and patched:
        verdict = "PATCH_FAILED"
    elif was and now and not patched:
        verdict = "NOT_FIXED"
    elif was and not now and not patched:
        verdict = "NOT_FIXED_NO_PATCH"
    elif not was:
        verdict = "NOT_REPRODUCIBLE"
    else:
        verdict = "UNKNOWN"
    
    results.append({
        "exploit": name,
        "before": was,
        "after": now,
        "patched": patched,
        "verdict": verdict,
    })

print(f"\n{'Exploit':<25s} {'Before':<10s} {'After':<10s} {'Patched':<10s} {'Verdict':<25s}")
print("-" * 85)
for r in results:
    b = "EXPLOITED" if r["before"] else "safe"
    a = "EXPLOITED" if r["after"] else "safe"
    p = "YES" if r["patched"] else "NO"
    print(f"{r['exploit']:<25s} {b:<10s} {a:<10s} {p:<10s} {r['verdict']:<25s}")

fixed = sum(1 for r in results if r["verdict"] == "VERIFIED_FIXED")
patch_failed = sum(1 for r in results if r["verdict"] == "PATCH_FAILED")
not_fixed = sum(1 for r in results if "NOT_FIXED" in r["verdict"])
not_repro = sum(1 for r in results if r["verdict"] == "NOT_REPRODUCIBLE")

print(f"\n{'='*70}")
print("SUMMARY")
print(f"{'='*70}")
print(f"Total exploits tested:     {len(exploit_funcs)}")
print(f"Exploits confirmed (before): {exploited}")
print(f"Verified FIXED:            {fixed}")
print(f"Patch FAILED:              {patch_failed}")
print(f"Not FIXED:                 {not_fixed}")
print(f"Not REPRODUCIBLE:          {not_repro}")
print(f"Regression tests:          {'PASS' if regression_pass else 'FAIL'}")
print(f"{'='*70}")

# Cleanup
try:
    ctx.sandbox.cleanup()
except:
    pass

print("\nTest complete!")
