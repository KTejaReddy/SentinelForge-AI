"""Deterministic test of the auto-repair machinery.

Simulates the Repair Agent's output (canned patch for the demo's command
injection) and verifies the full loop:
  reproduce BEFORE -> apply patch -> rebuild+restart -> reproduce AFTER
  -> regression tests -> verification verdict.

Usage: python scripts/test_repair.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import scripts_helper  # noqa: E402,F401  (utf-8 console)
from config import UPLOADS_DIR, WORKSPACES_DIR  # noqa: E402
from database import SessionLocal, init_db  # noqa: E402
from models import Project, Scan  # noqa: E402
from security import make_zip  # noqa: E402

PATCH = {
    "files": {
        "server.js": {
            "old": (
                '  const host = String(req.query.host || "127.0.0.1");\n'
                "  // INTENTIONALLY UNSAFE: host flows straight into a shell command\n"
                '  const cmd = process.platform === "win32" ? "ping -n 1 " + host : "ping -c 1 " + host;\n'
            ),
            "new": (
                '  const host = String(req.query.host || "127.0.0.1");\n'
                "  if (!/^[0-9a-zA-Z.:-]+$/.test(host)) {\n"
                '    return res.status(400).json({ error: "invalid host" });\n'
                "  }\n"
                '  const cmd = process.platform === "win32" ? "ping -n 1 " + host : "ping -c 1 " + host;\n'
            ),
        }
    },
    "explanation": "Add a strict hostname allowlist before exec to block command injection.",
}


def main() -> int:
    init_db()
    demo_dir = ROOT / "demo" / "vulnerable-app"
    zip_path = Path(UPLOADS_DIR) / "repair-test.zip"
    make_zip(demo_dir, zip_path, exclude=("node_modules",))
    data = zip_path.read_bytes()

    db = SessionLocal()
    try:
        project = Project(name="repair-test", filename="repair-test.zip", sha256="repair-test-fixed-sha", size_bytes=len(data), status="UPLOADED")
        db.add(project)
        db.commit()
        db.refresh(project)
        (Path(UPLOADS_DIR) / f"{project.id}.zip").write_bytes(data)
        scan = Scan(project_id=project.id, state="UPLOADED", status="UPLOADED", intensity="standard", options=json.dumps({}))
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    # --- build a minimal ctx and start the app ------------------------------------
    import shutil
    from services.scan_context import ScanContext
    from services.project_detector import detect_project
    from orchestrator.build import build_and_start
    from orchestrator.repair import reproduce_finding, _repair_one
    from services.ai.groq_client import GroqClient

    workspace = Path(WORKSPACES_DIR) / f"scan-{scan_id}"
    for d in ("original", "working-copy", "patched-copy"):
        shutil.rmtree(workspace / d, ignore_errors=True)
        (workspace / d).mkdir(parents=True, exist_ok=True)
    from security import secure_extract_zip

    secure_extract_zip(data, workspace / "original")
    shutil.copytree(workspace / "original", workspace / "working-copy", dirs_exist_ok=True)

    ctx = ScanContext(scan_id=scan_id, project_id=project.id, project_name="repair-test", workspace=workspace,
                      original=workspace / "original", working=workspace / "working-copy",
                      patched=workspace / "patched-copy", options={}, intensity="standard")
    ctx.detection = detect_project(ctx.working)

    info = build_and_start(ctx)
    assert info.get("base_url") and info.get("started"), f"app failed to start: {info}"
    ctx.runtime = info
    print("app running at", info["base_url"])

    finding = {
        "title": "Command injection (confirmed)",
        "category": "injection",
        "severity": "CRITICAL",
        "confidence": 0.9,
        "source": "dynamic",
        "affected_component": "/api/ping",
        "affected_file": "server.js",
        "line_start": 83,
        "reproduction": {
            "method": "GET", "path": "/api/ping",
            "params": {"host": "127.0.0.1; echo SFCMDIPWNED"},
            "expect": {"contains": "SFCMDIPWNED"},
            "tool": "dynamic",
        },
        "evidence": {"tool": "dynamic"},
        "patch_status": "none",
        "status": "open",
    }
    ctx.findings_bank = [finding]

    before = reproduce_finding(ctx, finding)
    print("BEFORE patch: exploited =", before.get("exploited"), "| status =", before.get("status_code"))
    assert before.get("exploited") is True, "exploit did not reproduce before patch!"

    # --- simulate the Repair Agent ------------------------------------------------
    import orchestrator.repair as repair_mod

    orig_agent = repair_mod.run_repair_agent
    repair_mod.run_repair_agent = lambda c, f: (PATCH, "")
    # give verification_agent a stub too (AI unavailable in CI)
    import agents.verification_agent as verif_mod

    repair_mod.decide_verification = verif_mod.decide_verification  # keep real decision fn

    stats = {"patched": 0, "verified": 0, "failed": 0, "reverted": 0, "iterations": 0}
    try:
        _repair_one(ctx, finding, stats)
    finally:
        repair_mod.run_repair_agent = orig_agent

    after = reproduce_finding(ctx, finding)
    print("AFTER patch: exploited =", after.get("exploited"), "| status =", after.get("status_code"))
    print("finding.patch_status =", finding.get("patch_status"), "| finding.status =", finding.get("status"))
    print("stats =", stats)

    assert after.get("exploited") is False, "exploit still works after patch!"
    assert finding.get("patch_status") == "verified", "patch not verified"
    assert stats.get("verified") >= 1, "verification not recorded"

    # confirm the working copy contains the fix and original is untouched
    working = (ctx.working / "server.js").read_text(encoding="utf-8")
    original = (ctx.original / "server.js").read_text(encoding="utf-8")
    assert "invalid host" in working, "fix not present in working copy"
    assert "invalid host" not in original, "original copy was mutated!"
    print("\nPASS: patch applied, verified, original untouched.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
