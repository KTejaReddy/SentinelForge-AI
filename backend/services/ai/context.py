"""Context management for AI agents.

Builds compact, relevant prompts: prioritized files, truncated content,
summarized scanner output, runtime logs. Never dumps the whole project.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from config import settings

PRIORITY_MARKERS = [
    ("route", r"(route|router|@app|@\w+\.(get|post|put|delete)|\.get\(|\.post\(|Mapping)"),
    ("auth", r"(?i)(auth|login|session|token|password|jwt|permission|role)"),
    ("db", r"(?i)(sql|query|execute|select |insert |update |delete |mongoose|sqlalchemy|prisma|knex)"),
    ("upload", r"(?i)(upload|multer|multipart|file|path\.join|readFile)"),
    ("unsafe", r"(?i)(eval|exec\(|child_process|os\.system|pickle|yaml\.load|innerHTML)"),
    ("config", r"(?i)(cors|helmet|cookie|session|secret|debug)"),
]

SOURCE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".java", ".yml", ".yaml", ".json", ".sql", ".html", ".vue", ".svelte"}


def prioritize_files(root: Path, limit: int | None = None, max_bytes: int | None = None) -> list[Path]:
    limit = limit or settings.max_context_files
    max_bytes = max_bytes or settings.max_single_file_bytes
    files: list[tuple[int, Path]] = []
    try:
        for p in root.rglob("*"):
            if not p.is_file() or p.is_symlink():
                continue
            rel = p.relative_to(root)
            if any(part in {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".next", "target", "coverage", ".sf-home", "artifacts"} for part in rel.parts):
                continue
            if p.suffix not in SOURCE_EXT or p.stat().st_size > max_bytes:
                continue
            if p.stat().st_size == 0:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            score = 1
            for _, pattern in PRIORITY_MARKERS:
                if re.search(pattern, text[:50_000]):
                    score += 2
            files.append((score, p))
    except OSError:
        pass
    files.sort(key=lambda t: (-t[0], str(t[1])))
    return [p for _, p in files[:limit]]


def file_snapshot(path: Path, max_bytes: int | None = None) -> str:
    max_bytes = max_bytes or settings.max_single_file_bytes
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(text) > max_bytes:
        text = text[:max_bytes] + f"\n… [truncated, {len(text)} total chars]"
    return text


def build_project_context(ctx: Any, focus_files: list[str] | None = None, max_files: int = 12) -> str:
    """Compact project context for agent prompts."""
    parts: list[str] = []
    det = ctx.detection or {}
    parts.append("## Project metadata")
    parts.append(
        f"- type: {det.get('project_type')}\n"
        f"- languages: {', '.join(list((det.get('languages') or {}).keys())[:6])}\n"
        f"- frameworks: {', '.join(det.get('frameworks') or [])}\n"
        f"- package managers: {', '.join((det.get('package_managers') or {}).keys())}\n"
        f"- entrypoints: {', '.join(det.get('entrypoints') or [])}\n"
        f"- ports: {det.get('ports')}\n"
        f"- auth indicators: {', '.join((det.get('auth_indicators') or [])[:8])}\n"
        f"- db deps: {', '.join((det.get('database_dependencies') or [])[:8])}\n"
    )
    rm = ctx.route_map or {}
    routes = rm.get("routes") or []
    if routes:
        parts.append("## Routes discovered")
        parts.append("\n".join(f"- {r.get('methods')} {r.get('path')} [{r.get('source_file')}:{r.get('line')}]" for r in routes[:40]))

    parts.append("## Relevant source files")
    selected: list[Path] = []
    if focus_files:
        for f in focus_files:
            cand = ctx.working / f
            if cand.exists():
                selected.append(cand)
    if not selected:
        selected = prioritize_files(ctx.working, limit=max_files)
    for path in selected:
        rel = path.relative_to(ctx.working)
        parts.append(f"\n### {rel}\n```\n{file_snapshot(path, max_bytes=8000)}\n```")
    return "\n".join(parts)


def summarize_logs(text: str, limit: int = 2500) -> str:
    if not text:
        return "(no logs)"
    lines = text.splitlines()
    tail = lines[-60:]
    return "\n".join(tail)[-limit:]


def summarize_findings(findings: list[dict[str, Any]], limit: int = 12) -> str:
    if not findings:
        return "(no findings yet)"
    rows = []
    for f in findings[:limit]:
        rows.append(
            f"- [{f.get('severity')}] {f.get('title')} ({f.get('source')}) file={f.get('affected_file')}:{f.get('line_start')} "
            f"conf={f.get('confidence')}"
        )
    return "\n".join(rows)
