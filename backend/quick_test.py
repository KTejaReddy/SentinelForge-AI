"""Quick step-by-step test of the scan pipeline components."""
import os
import sys
import time
import shutil
import socket
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
bin_dir = ROOT_DIR / "tools" / "bin"
if bin_dir.exists():
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

from services.project_detector import detect_project
from config import WORKSPACES_DIR, UPLOADS_DIR
from security import secure_extract_zip, make_zip
from utils.process import ProcessSpec, run_process

# 1. Extract
print("=== Step 1: Extract ===")
workspace = Path(WORKSPACES_DIR) / "scan-quick"
original = workspace / "original"
working = workspace / "working-copy"
for d in (original, working):
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True, exist_ok=True)

demo_dir = ROOT_DIR / "demo" / "vulnerable-app"
zip_path = Path(UPLOADS_DIR) / "e2e-test-vulnerable.zip"
if not zip_path.exists():
    make_zip(demo_dir, zip_path, exclude=("node_modules", ".git"))
data = zip_path.read_bytes()
secure_extract_zip(data, original)
for item in original.rglob("*"):
    if item.is_symlink(): continue
    rel = item.relative_to(original)
    if any(part in {"node_modules", ".git", "__pycache__"} for part in rel.parts): continue
    target = working / rel
    if item.is_dir():
        target.mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target)
print("OK")

# 2. Detect
print("\n=== Step 2: Detect ===")
det = detect_project(working)
print(f"Type: {det['project_type']}, Frameworks: {det['frameworks']}")
print(f"Commands: {det['commands']}")
sys.stdout.flush()

# 3. npm install
print("\n=== Step 3: npm install ===")
t0 = time.time()
res = run_process(ProcessSpec(cmd=["npm", "install"], cwd=str(working), timeout_s=60))
print(f"Exit: {res.exit_code}, Time: {time.time()-t0:.1f}s")
sys.stdout.flush()

# 4. Start server
print("\n=== Step 4: Start server ===")
s = socket.socket()
s.bind(("", 0))
port = s.getsockname()[1]
s.close()
print(f"Port: {port}")

proc = subprocess.Popen(
    ["node", "server.js"],
    cwd=str(working),
    env={**os.environ, "PORT": str(port), "NODE_ENV": "test", "CI": "1", "HOST": "127.0.0.1"},
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
)
print(f"PID: {proc.pid}")
time.sleep(3)

# 5. Health check
print("\n=== Step 5: Health check ===")
import httpx
try:
    r = httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=5)
    print(f"Status: {r.status_code}, Body: {r.text[:100]}")
except Exception as e:
    print(f"Health failed: {e}")

# 6. Test dynamic probing
print("\n=== Step 6: Dynamic probes ===")
from services.probes.http import probe
for path in ["/api/health", "/api/search?q=test", "/api/ping?host=127.0.0.1"]:
    try:
        r = probe("GET", f"http://127.0.0.1:{port}{path}", timeout_s=5)
        print(f"  GET {path} -> {r.status_code} ({len(r.text)} bytes)")
    except Exception as e:
        print(f"  GET {path} -> ERROR: {e}")

# 7. Cleanup
proc.terminate()
try:
    proc.wait(timeout=5)
except:
    proc.kill()
print("\n=== Done ===")
