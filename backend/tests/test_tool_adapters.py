"""Tests for tool adapters and the capability registry."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.scan_context import ScanContext  # noqa: E402
from tools.registry import list_tools  # noqa: E402


def _ctx(tmp_path: Path, files: dict[str, str]) -> ScanContext:
    root = tmp_path / "ws"
    working = root / "working-copy"
    for rel, content in files.items():
        f = working / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    return ScanContext(scan_id=1, project_id=1, project_name="t", workspace=root, original=root / "original", working=working, patched=root / "patched-copy", options={}, intensity="standard")


def test_registry_includes_new_adapters() -> None:
    names = {t.name for t in list_tools()}
    assert {
        "Semgrep", "Trivy", "Gitleaks", "OWASP ZAP", "Nuclei", "ffuf",
        "Browser Agent", "Bandit (Python SAST)", "OSV-Scanner",
    } <= names


def test_bandit_finds_unsafe_python(tmp_path: Path) -> None:
    from tools.bandit import BanditAdapter

    adapter = BanditAdapter()
    if not adapter.detect():
        pytest.skip("bandit not installed")
    ctx = _ctx(tmp_path, {
        "app.py": "import subprocess\nuser_input = input()\nsubprocess.call(user_input, shell=True)\n",
    })
    findings = adapter.run(ctx)
    assert findings, "bandit should flag subprocess with shell=True"
    assert findings[0]["source"] == "bandit"
    assert findings[0]["affected_file"] == "app.py"


def test_bandit_skips_non_python(tmp_path: Path) -> None:
    from tools.bandit import BanditAdapter

    ctx = _ctx(tmp_path, {"server.js": "const x = 1;\n"})
    assert BanditAdapter().run(ctx) == []


def test_osv_scanner_runs_and_normalizes(tmp_path: Path) -> None:
    from tools.osv_scanner import OsvScannerAdapter

    adapter = OsvScannerAdapter()
    if not adapter.detect():
        pytest.skip("osv-scanner not installed")
    ctx = _ctx(tmp_path, {
        "package.json": '{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}',
    })
    findings = adapter.run(ctx)  # may need network; must not raise
    for f in findings:
        assert f["source"] == "osv-scanner"
        assert f["category"] == "dependencies"
