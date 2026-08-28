"""Safe agent tools.

Every tool the model can call is implemented here - validated, logged,
time-limited, and scoped to the scan workspace. There is deliberately NO
raw shell execution: tools are read-only inspection, bounded probing, or
bounded test runs. Command strings from the model are never executed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from services.probes.http import probe
from utils.process import ProcessSpec, run_process


def _resolve_in_workspace(ctx: Any, path_str: str) -> Path | None:
    """Resolve a relative path inside the scan workspace; reject traversal."""
    roots = [ctx.workspace, ctx.working, ctx.original, ctx.patched]
    candidate = None
    for root in roots:
        cand = (root / path_str).resolve()
        if cand.exists() and any(cand.is_relative_to(r.resolve()) for r in roots):
            candidate = cand
            break
    if candidate is None:
        cand = (ctx.working / path_str).resolve()
        if cand.is_relative_to(ctx.working.resolve()):
            candidate = cand
    return candidate


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOL_DEFS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "inspect_project_tree",
            "description": "List files/directories inside the project workspace (excludes node_modules, .git).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Subdirectory relative to project root (default: .)"},
                    "max_depth": {"type": "integer", "description": "Depth limit (default 3)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_file",
            "description": "Read a source file from the project (relative path). Truncated to ~12k chars.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Relative file path, e.g. server.js"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Regex search across project source files. Returns file:line matches.",
            "parameters": {
                "type": "object",
                "properties": {"pattern": {"type": "string", "description": "Regex, e.g. 'exec\\(' or 'authorization'"}},
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_route_map",
            "description": "Get the discovered HTTP routes/APIs of the running app.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_detection",
            "description": "Get project fingerprint metadata (languages, frameworks, commands, entrypoints).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_runtime_logs",
            "description": "Get the application runtime stdout/stderr (tail).",
            "parameters": {
                "type": "object",
                "properties": {"tail": {"type": "integer", "description": "lines to return"}},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings",
            "description": "Get current normalized findings from scanners and probes.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_project_tests",
            "description": "Run the project's native test suite in the sandbox (bounded, returns exit code + tail).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_targeted_probe",
            "description": "Send a single HTTP request to the sandboxed app (loopback only). Bounded time.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]},
                    "path": {"type": "string", "description": "Path starting with /"},
                    "body": {"type": "string", "description": "Optional request body"},
                },
                "required": ["method", "path"],
            },
        },
    },
]

TOOL_FUNCS: dict[str, Callable[..., Any]] = {}


def _register(name: str):
    def deco(fn: Callable[..., Any]):
        TOOL_FUNCS[name] = fn
        return fn
    return deco


@_register("inspect_project_tree")
def _inspect_tree(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    sub = (args.get("path") or "").strip().lstrip("/")
    root = (ctx.working / sub).resolve() if sub else ctx.working.resolve()
    if not root.is_relative_to(ctx.working.resolve()):
        return {"error": "path outside workspace"}
    max_depth = int(args.get("max_depth") or 3)
    out = []
    try:
        for p in sorted(root.rglob("*"))[:400]:
            rel = p.relative_to(ctx.working)
            if any(part in {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", ".next", "artifacts"} for part in rel.parts):
                continue
            if len(rel.parts) > max_depth:
                continue
            out.append(("DIR " if p.is_dir() else "FILE") + " " + rel.as_posix())
    except OSError as exc:
        return {"error": str(exc)}
    return {"entries": out[:300], "count": len(out)}


@_register("inspect_file")
def _inspect_file(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    path = _resolve_in_workspace(ctx, args.get("path", ""))
    if not path or not path.is_file():
        return {"error": f"file not found: {args.get('path')}"}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"error": str(exc)}
    return {"path": str(path.relative_to(ctx.working)), "content": text[:12_000]}


@_register("search_code")
def _search_code(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    try:
        pattern = re.compile(args.get("pattern", ""))
    except re.error as exc:
        return {"error": f"bad regex: {exc}"}
    matches = []
    for p in ctx.working.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(ctx.working)
        if any(part in {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", ".next", "artifacts"} for part in rel.parts):
            continue
        if p.suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".java", ".html"}:
            continue
        try:
            for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if pattern.search(line):
                    matches.append(f"{rel.as_posix()}:{i}: {line.strip()[:180]}")
                    if len(matches) >= 60:
                        return {"matches": matches, "count": "60+ (truncated)"}
        except OSError:
            continue
    return {"matches": matches, "count": len(matches)}


@_register("get_route_map")
def _get_route_map(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    return {"routes": (ctx.route_map or {}).get("routes", [])}


@_register("get_detection")
def _get_detection(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    return {"detection": ctx.detection}


@_register("get_runtime_logs")
def _get_runtime_logs(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    tail = int(args.get("tail") or 80)
    return {"logs": (ctx.runtime_log or "")[-tail * 400:]}


@_register("get_findings")
def _get_findings(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    return {"findings": ctx.findings_bank[:60]}


@_register("run_project_tests")
def _run_tests(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    test_cmd = (ctx.detection.get("commands") or {}).get("test")
    if not test_cmd:
        return {"error": "no test command detected"}
    res = ctx.sandbox.run(test_cmd.split(), cwd=ctx.working, timeout_s=600)
    return {"exit_code": res.exit_code, "output_tail": (res.stdout + res.stderr)[-3000:]}


@_register("run_targeted_probe")
def _targeted_probe(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    base_url = ctx.runtime.get("base_url")
    if not base_url:
        return {"error": "application not running"}
    method = (args.get("method") or "GET").upper()
    path = (args.get("path") or "/").lstrip("/")
    url = base_url.rstrip("/") + "/" + path
    try:
        resp = probe(method, url, timeout_s=8, content=args.get("body") if method in ("POST", "PUT", "PATCH") else None)
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": (resp.text or "")[:4000],
        }
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": f"request failed: {exc}"}
