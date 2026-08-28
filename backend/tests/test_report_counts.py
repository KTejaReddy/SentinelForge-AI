"""Tests for report counting (severity + fix status)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.report import _counts  # noqa: E402
from tools.base import make_finding  # noqa: E402


def test_counts_severities_correctly() -> None:
    findings = [
        make_finding("cmd injection", "injection", severity="CRITICAL"),
        make_finding("path traversal", "file_security", severity="CRITICAL"),
        make_finding("idor", "authorization", severity="HIGH"),
        make_finding("xss", "xss", severity="MEDIUM"),
        make_finding("headers", "configuration", severity="LOW"),
    ]
    c = _counts(findings)
    assert c["critical"] == 2
    assert c["high"] == 1
    assert c["medium"] == 1
    assert c["low"] == 1
    assert c["findings_total"] == 5


def test_counts_verified_and_status() -> None:
    fixed = make_finding("a", "injection", severity="HIGH")
    fixed["patch_status"] = "verified"
    fixed["status"] = "fixed"
    review = make_finding("b", "xss", severity="MEDIUM")
    review["status"] = "needs_review"
    c = _counts([fixed, review])
    assert c["verified"] == 1
    assert c["fixed"] == 1
    assert c["needs_review"] == 1
