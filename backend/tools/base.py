"""Tool adapter contract.

    ToolAdapter
        detect()        -> bool  (is this tool usable right now?)
        version()       -> str | None
        install_hint()  -> str
        run(ctx)        -> list[RawFinding]  (real results or empty)
        normalize(...)  -> Finding dict (single internal schema)

Optional tools are never required: if detect() is False the step is
recorded as SKIPPED/UNAVAILABLE and the scan continues.
"""
from __future__ import annotations

import hashlib
import re
import time
from abc import ABC, abstractmethod
from typing import Any

from events import log, tool_event
from services.scan_context import ScanContext

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def normalize_severity(value: str, default: str = "MEDIUM") -> str:
    v = (value or "").upper()
    for s in SEVERITIES:
        if s in v:
            return s
    return default


def clamp_confidence(value: float) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.5


def dedup_key(finding: dict[str, Any]) -> str:
    """Deterministic dedup across tools: category + file + line + normalized title."""
    title = re.sub(r"[^a-z0-9]+", "", (finding.get("title") or "").lower())[:80]
    return hashlib.sha1(
        f"{finding.get('category','')}|{finding.get('affected_file','')}|{finding.get('line_start','')}|{title}".encode()
    ).hexdigest()


def make_finding(
    title: str,
    category: str,
    severity: str = "MEDIUM",
    confidence: float = 0.6,
    source: str = "tool",
    affected_component: str = "",
    affected_file: str = "",
    line_start: int | None = None,
    line_end: int | None = None,
    description: str = "",
    why_it_matters: str = "",
    evidence: dict[str, Any] | None = None,
    reproduction: dict[str, Any] | None = None,
    provenance: str = "Observed",
) -> dict[str, Any]:
    """One finding in the single internal schema (see §15)."""
    return {
        "title": title,
        "category": category,
        "severity": normalize_severity(severity),
        "confidence": clamp_confidence(confidence),
        "source": source,
        "affected_component": affected_component,
        "affected_file": affected_file,
        "line_start": line_start,
        "line_end": line_end,
        "description": description,
        "why_it_matters": why_it_matters,
        "evidence": evidence or {},
        "reproduction": reproduction or {},
        "root_cause": "",
        "ai_explanation": "",
        "recommended_fix": "",
        "patch_status": "none",
        "provenance": provenance,
        "status": "open",
    }


class ToolAdapter(ABC):
    name: str = "tool"
    display_name: str = "Tool"

    @abstractmethod
    def detect(self) -> bool: ...

    def version(self) -> str | None:
        return None

    @abstractmethod
    def install_hint(self) -> str: ...

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        """Execute and return raw findings (normalized via make_finding)."""

    def fallback(self, ctx: ScanContext) -> list[dict[str, Any]]:
        """Deterministic fallback analyzer when the tool is unavailable.
        Default: no results + a recorded limitation."""
        ctx.add_limitation(f"{self.display_name} unavailable - {self.install_hint()}")
        return []

    def execute(self, ctx: ScanContext) -> list[dict[str, Any]]:
        """Wrapper with availability handling, fallback, logging, timing, and a persisted ToolRun."""
        start = time.time()
        if not self.detect():
            tool_event(ctx.scan_id, self.display_name, "UNAVAILABLE", self.install_hint())
            try:
                findings = self.fallback(ctx) or []
                if findings:
                    tool_event(ctx.scan_id, self.display_name, "DONE", f"fallback analyzer: {len(findings)} finding(s)")
                _record_run(ctx, self.display_name, "FALLBACK" if findings else "UNAVAILABLE", start, len(findings))
                return findings
            except Exception as exc:
                ctx.add_limitation(f"{self.display_name} fallback failed: {exc}")
                _record_run(ctx, self.display_name, "FAILED", start, 0, error=str(exc)[:200])
                return []
            finally:
                duration = int((time.time() - start) * 1000)
                ctx.tool_results[self.name] = {"duration_ms": duration, "engine": "fallback"}
        tool_event(ctx.scan_id, self.display_name, "RUNNING")
        log(ctx.scan_id, f"Running {self.display_name}")
        try:
            findings = self.run(ctx) or []
            tool_event(ctx.scan_id, self.display_name, "DONE", f"{len(findings)} finding(s)")
            _record_run(ctx, self.display_name, "DONE", start, len(findings))
            return findings
        except Exception as exc:  # never let one tool kill the scan
            tool_event(ctx.scan_id, self.display_name, "FAILED", str(exc)[:300])
            ctx.add_limitation(f"{self.display_name} failed: {exc}")
            log(ctx.scan_id, f"{self.display_name} failed: {exc}", level="warn")
            _record_run(ctx, self.display_name, "FAILED", start, 0, error=str(exc)[:200])
            return []
        finally:
            duration = int((time.time() - start) * 1000)
            ctx.tool_results[self.name] = {"duration_ms": duration}


def _record_run(ctx: ScanContext, tool: str, status: str, start: float, finding_count: int, error: str = "") -> None:
    """Persist one ToolRun row (status: RUNNING/DONE/FAILED/UNAVAILABLE/FALLBACK)."""
    try:
        from database import SessionLocal
        from models import ToolRun

        db = SessionLocal()
        try:
            db.add(ToolRun(
                scan_id=ctx.scan_id,
                tool=tool,
                status=status,
                duration_ms=int((time.time() - start) * 1000),
                summary={"findings": finding_count, "error": error[:200]} if error else {"findings": finding_count},
            ))
            db.commit()
        finally:
            db.close()
    except Exception:
        pass  # tool-run bookkeeping must never break a scan
