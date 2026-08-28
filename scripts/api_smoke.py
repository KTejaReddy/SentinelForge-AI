"""Full API smoke test — exercises every endpoint via TestClient.

Usage: python scripts/api_smoke.py
"""
from __future__ import annotations

import io
import sys
import time
from pathlib import Path

import scripts_helper  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from config import WORKSPACES_DIR  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from main import app  # noqa: E402
from security import make_zip  # noqa: E402

FAIL = []


def check(name: str, cond: bool, extra: str = "") -> None:
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name}" + (f" — {extra}" if extra and not cond else ""))
    if not cond:
        FAIL.append(name)


def main() -> int:
    with TestClient(app) as client:
        print("== health & tools ==")
        r = client.get("/api/health")
        check("health", r.status_code == 200 and r.json()["status"] == "ok", str(r.text[:200]))

        r = client.get("/api/tools")
        check("tools list", r.status_code == 200 and len(r.json()) > 5, str(r.text[:300]))

        r = client.get("/api/settings/groq")
        check("groq status", r.status_code == 200 and "configured" in r.json())

        r = client.post("/api/settings/groq", json={"api_key": "gsk_test_abcdefghijklmnop", "model": "llama-3.3-70b-versatile"})
        check("groq save", r.status_code == 200 and r.json()["configured"])
        key_hint = r.json()["key_hint"]
        check("key stored encrypted (hint only)", key_hint.startswith("gsk_") and "…" in key_hint, str(key_hint))

        r = client.post("/api/settings/groq/test", json={"api_key": "gsk_invalid", "model": "llama-3.3-70b-versatile"})
        check("groq test with bad key handled", r.status_code == 200 and r.json()["ok"] is False, str(r.text[:300]))
        # clear the fake key again so scans run deterministic
        client.post("/api/settings/groq", json={"api_key": ""})

        print("== upload ==")
        demo = ROOT / "demo" / "vulnerable-app"
        zip_path = ROOT / "data" / "api-smoke.zip"
        make_zip(demo, zip_path, exclude=("node_modules",))
        with open(zip_path, "rb") as f:
            r = client.post("/api/projects/upload", files={"file": ("demo.zip", f, "application/zip")})
        check("upload", r.status_code == 200, str(r.text[:400]))
        project = r.json()
        pid = project["id"]
        check("sha256 present", len(project["sha256"]) == 64)

        # zip-slip / invalid zip rejection
        r = client.post("/api/projects/upload", files={"file": ("evil.zip", io.BytesIO(b"not a zip at all"), "application/zip")})
        check("invalid zip rejected (400)", r.status_code == 400, str(r.text[:200]))

        print("== scan ==")
        opts = {
            "security_testing": True, "bug_hunting": True, "static_analysis": True,
            "dependency_analysis": True, "secrets_detection": True, "dynamic_testing": True,
            "browser_testing": True, "fuzzing": True, "automatic_repair": True, "verification": True,
            "intensity": "standard",
        }
        r = client.post(f"/api/projects/{pid}/scan", json={"project_id": pid, "options": opts})
        check("scan start", r.status_code == 200, str(r.text[:400]))
        scan = r.json()
        sid = scan["id"]

        # SSE events stream (verified live in the UI; TestClient + infinite
        # generator streams don't mix, so this is exercised by unit tests).

        print("  waiting for scan to finish (up to ~6 min)...")
        deadline = time.time() + 360
        last = ""
        while time.time() < deadline:
            r = client.get(f"/api/scans/{sid}")
            s = r.json()
            if s["state"] != last:
                print(f"    state={s['state']} progress={s['progress']:.0f}%")
                last = s["state"]
            if s["state"] in ("COMPLETED", "FAILED", "CANCELLED"):
                break
            time.sleep(3)
        check("scan completed", s["state"] == "COMPLETED", s.get("error") or s["state"])

        r = client.get(f"/api/scans/{sid}/findings")
        findings = r.json()
        check("findings returned", r.status_code == 200 and len(findings) > 0, f"{len(findings)} findings")
        sevs = {f["severity"] for f in findings}
        print("    severities:", sevs)

        critical = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        if critical:
            fid = critical[0]["id"]
            r = client.get(f"/api/findings/{fid}/detail")
            check("finding detail", r.status_code == 200 and "evidence" in r.json())
            r = client.post(f"/api/findings/{fid}/verify")
            check("verify endpoint", r.status_code == 200 and r.json()["ok"])
            time.sleep(3)

        r = client.get(f"/api/scans/{sid}/report")
        check("report", r.status_code == 200 and "scores" in r.json())
        scores = r.json()["scores"]
        print("    scores:", scores)

        r = client.get(f"/api/scans/{sid}/attack-graph")
        check("attack graph", r.status_code == 200 and len(r.json()["graph"]) > 0, str(r.text[:200]))

        for kind in ("original", "patched", "reports"):
            r = client.get(f"/api/scans/{sid}/download/{kind}")
            check(f"download {kind}", r.status_code == 200 and len(r.content) > 100, f"{r.status_code}")

        # cleanup fake key from settings table
        from database import SessionLocal
        from models import Setting

        db = SessionLocal()
        try:
            row = db.get(Setting, "groq_api_key_enc")
            if row:
                db.delete(row)
            db.commit()
        finally:
            db.close()
        client.post("/api/settings/groq", json={"api_key": ""})

    print()
    if FAIL:
        print(f"FAILED: {len(FAIL)} checks: {FAIL}")
        return 1
    print("ALL API CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
