"""Tests for the deterministic scoring formula."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.scoring import compute_scores  # noqa: E402


def _finding(severity: str, status: str = "open", patch_status: str = "none", category: str = "injection") -> dict:
    return {"title": "x", "category": category, "severity": severity, "confidence": 0.9, "status": status, "patch_status": patch_status, "source": "t"}


def test_clean_project_scores_100() -> None:
    s = compute_scores([])
    assert s["security"] == 100 and s["reliability"] == 100 and s["code_health"] == 100 and s["overall"] == 100


def test_severity_penalties() -> None:
    s = compute_scores([_finding("CRITICAL")])
    assert s["security"] == 80  # 100 - 20
    s2 = compute_scores([_finding("HIGH"), _finding("HIGH"), _finding("LOW")])
    assert s2["security"] == 78  # 100 - 10 - 10 - 2
    s3 = compute_scores([_finding("CRITICAL"), _finding("CRITICAL")])
    assert s3["security"] == 60


def test_verified_fix_no_penalty() -> None:
    s = compute_scores([_finding("CRITICAL", status="fixed", patch_status="verified")])
    assert s["security"] == 100


def test_applied_but_unverified_partial_penalty() -> None:
    s = compute_scores([_finding("HIGH", patch_status="applied")])
    assert s["security"] == 97  # 100 - 10*0.3


def test_deterministic() -> None:
    a = compute_scores([_finding("MEDIUM"), _finding("LOW")])
    b = compute_scores([_finding("MEDIUM"), _finding("LOW")])
    assert a == b


def test_native_test_failures_penalize_reliability() -> None:
    s = compute_scores([], tool_results={"native_tests": {"failed": 3}})
    assert s["reliability"] <= 94  # 100 - min(30, 6)
