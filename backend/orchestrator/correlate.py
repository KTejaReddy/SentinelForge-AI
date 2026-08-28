"""Finding correlation - normalize, dedupe, merge, and rank findings.

Equivalent findings from different tools (e.g. Semgrep + dynamic probe)
are merged into a single higher-confidence finding with combined sources.
"""
from __future__ import annotations

from typing import Any

from services.scan_context import ScanContext, SEVERITY_WEIGHT
from tools.base import dedup_key, make_finding


def correlate_findings(ctx: ScanContext) -> list[dict[str, Any]]:
    raw = ctx.findings_bank
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in raw:
        key = dedup_key(f)
        groups.setdefault(key, []).append(f)

    correlated: list[dict[str, Any]] = []
    for key, group in groups.items():
        if not group:
            continue
        primary = max(group, key=lambda f: (SEVERITY_WEIGHT.get(f.get("severity"), 0), f.get("confidence", 0)))
        sources = sorted({f.get("source", "") for f in group})
        evidence = _merge_evidence(group)
        reproduction = _pick_reproduction(group)
        merged = make_finding(
            title=primary.get("title", ""),
            category=primary.get("category", "other"),
            severity=primary.get("severity", "MEDIUM"),
            confidence=max(f.get("confidence", 0) for f in group),
            source="+".join(sources),
            affected_component=primary.get("affected_component", ""),
            affected_file=primary.get("affected_file", ""),
            line_start=primary.get("line_start"),
            line_end=primary.get("line_end"),
            description=_merge_descriptions(group),
            why_it_matters=next((f.get("why_it_matters", "") for f in group if f.get("why_it_matters")), ""),
            evidence=evidence,
            reproduction=reproduction,
            provenance=_best_provenance(group),
        )
        merged["dedup_key"] = key
        if len(group) > 1:
            merged["ai_explanation"] = f"Correlated from {len(group)} independent source(s): {', '.join(sources)}."
        correlated.append(merged)

    correlated.sort(key=lambda f: (-SEVERITY_WEIGHT.get(f.get("severity"), 0), -f.get("confidence", 0)))

    # Secondary dedup: same file + line + category flagged by different engines → merge
    by_location: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
    singles: list[dict[str, Any]] = []
    for f in correlated:
        if f.get("affected_file") and f.get("line_start") is not None:
            by_location.setdefault((f["affected_file"], f["line_start"], f.get("category", "")), []).append(f)
        else:
            singles.append(f)
    merged_out: list[dict[str, Any]] = []
    for group in by_location.values():
        if len(group) == 1:
            merged_out.append(group[0])
            continue
        primary = max(group, key=lambda f: (SEVERITY_WEIGHT.get(f.get("severity"), 0), f.get("confidence", 0)))
        others = [f for f in group if f is not primary]
        primary["source"] = "+".join(sorted({f.get("source", "") for f in group}))
        primary["confidence"] = max(f.get("confidence", 0) for f in group)
        primary["description"] = primary.get("description", "") + ("\n\n(also flagged by " + ", ".join(sorted({f.get("source", "") for f in others})) + ")" if others else "")
        merged_out.append(primary)
    merged_out.extend(singles)
    merged_out.sort(key=lambda f: (-SEVERITY_WEIGHT.get(f.get("severity"), 0), -f.get("confidence", 0)))
    return merged_out


def _merge_evidence(group: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {"tools": [], "items": []}
    for f in group:
        ev = f.get("evidence") or {}
        tool = ev.get("tool") or f.get("source", "")
        if tool not in merged["tools"]:
            merged["tools"].append(tool)
        merged["items"].append(ev)
    if group:
        merged["tool"] = "+".join(merged["tools"])
    return merged


def _pick_reproduction(group: list[dict[str, Any]]) -> dict[str, Any]:
    for f in sorted(group, key=lambda x: -bool((x.get("reproduction") or {}).get("method"))):
        rep = f.get("reproduction") or {}
        if rep.get("method") and rep.get("path"):
            return rep
    for f in group:
        if f.get("reproduction"):
            return f["reproduction"]
    return {}


def _merge_descriptions(group: list[dict[str, Any]]) -> str:
    seen: list[str] = []
    for f in group:
        d = (f.get("description") or "").strip()
        if d and d not in seen:
            seen.append(d)
    return "\n\n---\n\n".join(seen[:3])[:6000]


def _best_provenance(group: list[dict[str, Any]]) -> str:
    order = ["Confirmed", "Verified", "Observed", "Potential", "Inferred"]
    found = [f.get("provenance", "Observed") for f in group]
    for level in order:
        if level in found:
            return level
    return "Observed"
