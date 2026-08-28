"""Deterministic scoring (documented in README §Scoring).

- Every unfixed finding costs points by severity:
    CRITICAL 20 · HIGH 10 · MEDIUM 5 · LOW 2 · INFO 0
- Findings that were patched but not yet verified cost 30% of the penalty.
- Verified-fixed findings cost 0.
- Reliability is additionally penalized by failing native tests
  (2 points per failing test, capped at 30) and crashes (HIGH +8, MEDIUM +4).
- Security/Reliability/Code-health are rolled into an Overall score with
  fixed weights (45/30/25).

The formula is pure: identical findings ⇒ identical scores.
"""
from __future__ import annotations

from typing import Any

SEVERITY_PENALTY = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
CATEGORY_BREAKDOWN = [
    "authentication", "authorization", "injection", "api_security", "secrets",
    "dependencies", "configuration", "file_security", "business_logic",
    "frontend_security", "reliability",
]


def compute_scores(findings: list[dict[str, Any]], tool_results: dict[str, Any] | None = None) -> dict[str, Any]:
    tool_results = tool_results or {}
    sec_penalty = 0.0
    rel_penalty = 0.0
    health_penalty = 0.0
    by_category: dict[str, float] = {}

    for f in findings:
        severity = f.get("severity", "MEDIUM")
        penalty = SEVERITY_PENALTY.get(severity, 5)
        status = f.get("status", "open")
        patch_status = f.get("patch_status", "none")
        if status == "verified" or patch_status == "verified":
            penalty = 0.0
        elif patch_status == "applied" or status == "fixed":
            penalty *= 0.3
        category = f.get("category", "other")
        by_category[category] = by_category.get(category, 0) + penalty

        if category == "reliability":
            if severity == "HIGH":
                rel_penalty += 8
            elif severity == "MEDIUM":
                rel_penalty += 4
            else:
                rel_penalty += 1
        else:
            sec_penalty += penalty
            if category in ("code_quality", "configuration"):
                health_penalty += penalty * 0.5

    tests = tool_results.get("native_tests", {})
    failed = int(tests.get("failed", 0) or 0)
    if failed:
        rel_penalty += min(30, failed * 2)

    def clamp(v: float) -> int:
        return int(max(5, min(100, round(100 - v))))

    security_score = clamp(sec_penalty)
    reliability_score = clamp(rel_penalty)
    code_health = clamp(health_penalty)

    from config import settings

    overall = round(
        security_score * settings.score_w_security
        + reliability_score * settings.score_w_reliability
        + code_health * settings.score_w_code_health
    )

    category_scores: dict[str, int] = {}
    for cat in CATEGORY_BREAKDOWN:
        category_scores[cat] = clamp(by_category.get(cat, 0.0))
    category_scores["code_quality"] = code_health

    return {
        "security": security_score,
        "reliability": reliability_score,
        "code_health": code_health,
        "overall": overall,
        "categories": category_scores,
        "penalties": {"security": round(sec_penalty, 1), "reliability": round(rel_penalty, 1), "code_health": round(health_penalty, 1)},
    }
