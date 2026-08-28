"""Tests for patch validation and application."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.patching.patch_engine import apply_patch, validate_patch  # noqa: E402
from services.scan_context import ScanContext  # noqa: E402


def _ctx(tmp_path: Path) -> ScanContext:
    root = tmp_path / "ws"
    for d in ("original", "working-copy", "patched-copy"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "working-copy" / "server.js").write_text("const x = 1;\nconst cmd = exec(host);\n", encoding="utf-8")
    return ScanContext(scan_id=1, project_id=1, project_name="t", workspace=root, original=root / "original", working=root / "working-copy", patched=root / "patched-copy", options={}, intensity="standard")


def test_valid_patch_applies(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    patch = {"files": {"server.js": {"old": "const cmd = exec(host);", "new": "const cmd = safeExec(host);"}}}
    assert validate_patch(patch, ctx) == []
    ok, changed, diff = apply_patch(patch, ctx)
    assert ok and len(changed) == 1 and "safeExec" in diff
    assert "safeExec" in (ctx.working / "server.js").read_text(encoding="utf-8")


def test_path_traversal_rejected(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    patch = {"files": {"../../evil.txt": {"old": "a", "new": "b"}}}
    errors = validate_patch(patch, ctx)
    assert any("escape" in e for e in errors)


def test_missing_snippet_rejected(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    patch = {"files": {"server.js": {"old": "this does not exist", "new": "x"}}}
    errors = validate_patch(patch, ctx)
    assert any("not found" in e for e in errors)


def test_ambiguous_snippet_rejected(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    (ctx.working / "a.txt").write_text("dup\ndup\n", encoding="utf-8")
    patch = {"files": {"a.txt": {"old": "dup", "new": "new"}}}
    errors = validate_patch(patch, ctx)
    assert any("ambiguous" in e for e in errors)


def test_empty_patch_rejected(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    assert validate_patch({"files": {}}, ctx)
