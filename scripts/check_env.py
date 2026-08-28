"""Environment checker — reports what the platform can use right now.

Usage: python scripts/check_env.py
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import scripts_helper  # noqa: F401,E402


def main() -> int:
    print("SentinelForge AI - environment check")
    print("=" * 56)

    py = sys.version.split()[0]
    print(f"\nPython            : {py}")
    try:
        import fastapi
        print(f"FastAPI           : {fastapi.__version__}")
    except Exception:
        print("FastAPI           : MISSING (pip install -r requirements.txt)")
    try:
        import playwright  # noqa: F401
        print("Playwright        : installed")
    except Exception:
        print("Playwright        : not installed (browser agent uses HTTP crawl)")

    print("\nOptional security tools:")
    for tool in ("semgrep", "gitleaks", "trivy", "nuclei", "ffuf", "zap-cli", "docker"):
        path = shutil.which(tool)
        print(f"  {tool:<12}: {'✓ ' + path if path else '- not found'}")

    from services.sandbox import sandbox_mode

    print(f"\nSandbox mode      : {sandbox_mode()}  (docker or local-fallback)")
    print("AI (Groq)         : " + ("configured via env/.env" if _groq_env() else "not configured - deterministic mode"))

    frontend_built = (ROOT / "frontend" / "dist").exists()
    print(f"Frontend build    : {'present (served by backend at :8000)' if frontend_built else 'not built (run: cd frontend && npm run build)'}")

    print("\nSuggested next steps:")
    print("  1. pip install -r requirements.txt")
    print("  2. (optional) bash scripts/install_tools.sh")
    print("  3. bash scripts/dev.sh")
    print("  4. open http://127.0.0.1:5173 and click 'Load Demo'")
    return 0


def _groq_env() -> bool:
    import os

    return bool(os.environ.get("GROQ_API_KEY"))


if __name__ == "__main__":
    sys.exit(main())
