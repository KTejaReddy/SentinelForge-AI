"""Tests for built-in deterministic analyzers and loopback enforcement."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.probes.http import enforce_loopback  # noqa: E402
from services.probes.secrets import scan_secrets  # noqa: E402
from services.probes.static import scan_static  # noqa: E402


def _root(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


def test_loopback_enforcement() -> None:
    enforce_loopback("http://127.0.0.1:3000/x")
    enforce_loopback("http://localhost:3000/x")
    with pytest.raises(ValueError):
        enforce_loopback("http://example.com/x")
    with pytest.raises(ValueError):
        enforce_loopback("ftp://127.0.0.1/x")


def test_secret_scanner_finds_aws_and_jwt(tmp_path: Path) -> None:
    root = _root(tmp_path, {
        "config.js": 'const aws = "AKIAFAKEKEY123456789";\nconst jwtSecret = "super-secret-jwt-123456789";\n',
        "safe.py": "x = 1\n",
    })
    findings = scan_secrets(root)
    files = {f["affected_file"]: f for f in findings}
    assert "config.js" in files
    families = {f["evidence"]["pattern"] for f in findings}
    assert "AWS Access Key" in families
    assert "JWT Secret" in families


def test_static_analyzer_finds_injection_patterns(tmp_path: Path) -> None:
    root = _root(tmp_path, {
        "server.js": "const { exec } = require('child_process');\napp.get('/ping', (req,res) => exec('ping ' + req.query.host));\n",
        "page.html": "<script>document.getElementById('x').innerHTML = q;</script>\n",
    })
    findings = scan_static(root)
    cats = {f["category"] for f in findings}
    assert "injection" in cats
    assert "xss" in cats


def test_static_analyzer_ignores_node_modules(tmp_path: Path) -> None:
    root = _root(tmp_path, {
        "node_modules/pkg/index.js": "exec(req.query.host);\n",
        "src/ok.js": "const a = 1;\n",
    })
    findings = scan_static(root)
    assert all("node_modules" not in f["affected_file"] for f in findings)
