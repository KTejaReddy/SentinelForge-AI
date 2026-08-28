"""Tests for the built-in local demo applications."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "backend"))

DEMOS = ["vulnerable-app", "injection-app", "auth-app"]


@pytest.mark.parametrize("name", DEMOS)
def test_demo_has_package_json(name: str) -> None:
    pkg = ROOT / "demo" / name / "package.json"
    assert pkg.exists(), f"demo/{name}/package.json missing"
    meta = json.loads(pkg.read_text(encoding="utf-8"))
    assert meta.get("scripts", {}).get("start"), "demo must have a start script"
    assert meta.get("scripts", {}).get("test"), "demo must have a test script"


@pytest.mark.parametrize("name,expected_route", [
    ("vulnerable-app", "/api/ping"),
    ("injection-app", "/api/run"),
    ("auth-app", "/api/admin/users"),
])
def test_demo_exposes_intended_vulnerable_surface(name: str, expected_route: str) -> None:
    server = ROOT / "demo" / name / "server.js"
    assert server.exists()
    assert expected_route in server.read_text(encoding="utf-8")


def test_demo_registry_lists_all_demos() -> None:
    from api.routes import list_demos  # noqa: E402

    names = {d["name"] for d in list_demos()}
    assert {"vulnerable-app", "injection-app", "auth-app"} <= names
