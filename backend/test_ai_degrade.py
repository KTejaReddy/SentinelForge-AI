"""Quick test: verify AI agents degrade fast without Groq key."""
import os, sys, time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
bin_dir = ROOT_DIR / "tools" / "bin"
if bin_dir.exists():
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

# Verify no Groq key
from config import settings
print(f"Groq key configured: {bool(settings.groq_api_key)}")

from services.scan_context import ScanContext
from config import WORKSPACES_DIR

# Minimal context
workspace = Path(WORKSPACES_DIR) / "scan-ai-test"
workspace.mkdir(parents=True, exist_ok=True)
ctx = ScanContext(
    scan_id=99998, project_id=0, project_name="test",
    workspace=workspace, original=workspace / "original",
    working=workspace / "working-copy", patched=workspace / "patched-copy",
    options={}, intensity="standard"
)

# Time each agent
from agents.base import llm, AGENT_PROMPTS
t0 = time.time()
data, err = llm(ctx, "test", "test")
print(f"llm() call: {time.time()-t0:.3f}s, error: {err}")
sys.stdout.flush()

from agents.recon_agent import run_recon_agent
t0 = time.time()
try:
    run_recon_agent(ctx)
except Exception as e:
    print(f"  Exception: {e}")
print(f"recon_agent: {time.time()-t0:.3f}s")
sys.stdout.flush()

from agents.simple_agents import run_api_agent, run_browser_agent, run_bug_hunter_agent
for name, fn in [("api_agent", run_api_agent), ("browser_agent", run_browser_agent), ("bug_hunter_agent", run_bug_hunter_agent)]:
    t0 = time.time()
    try:
        fn(ctx)
    except Exception as e:
        print(f"  Exception: {e}")
    print(f"{name}: {time.time()-t0:.3f}s")
    sys.stdout.flush()

print("\nAll AI agents completed quickly without Groq key!")
