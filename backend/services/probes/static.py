"""Built-in deterministic static analyzer - used when Semgrep is unavailable.

Conservative regex-based source checks over the working copy. Every finding
is a real pattern match with file/line/snippet. Source is labeled
`static-fallback` so reports distinguish it from Semgrep.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

IGNORED = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".next", "target", "coverage", ".sf-home"}
TEXT_EXT = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".php", ".java", ".html", ".vue", ".svelte", ".env", ".yml", ".yaml", ".json"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Gemfile.lock", "composer.lock", "go.sum"}

# (id, title, category, severity, languages, regex)
CHECKS: list[tuple[str, str, str, str, tuple[str, ...], re.Pattern]] = [
    ("cmd-injection", "Potential command injection (child_process with user input)", "injection", "HIGH", (".js", ".jsx", ".ts", ".tsx"),
     re.compile(r"(?i)\b(exec|execSync|spawn|execFile)\s*\(\s*[^)]{0,120}?(req\.|query|params|body|headers)")),
    ("cmd-injection-py", "Potential command injection (os.system/subprocess with user input)", "injection", "HIGH", (".py",),
     re.compile(r"(?i)(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output))\s*\([^)]{0,160}?(request\.|args|form|json|data)")),
    ("unsafe-eval", "Unsafe dynamic evaluation (eval/exec) with user input", "injection", "HIGH", (".js", ".jsx", ".ts", ".tsx", ".py"),
     re.compile(r"(?i)\b(eval|exec|compile|Function)\s*\([^)]{0,120}?(req\.|query|params|body|headers|request\.|input|location\.search)")),
    ("xss-innerhtml", "Reflected XSS - user input assigned to innerHTML/document.write", "xss", "HIGH", (".js", ".jsx", ".ts", ".tsx", ".html", ".vue"),
     re.compile(r"(?i)(innerHTML\s*=\s*(?!['\"`])|document\.write\s*\([^)]*?(req\.|query|params|body|headers|location\.search|URLSearchParams))[^;]{0,200}")),
    ("path-traversal", "Potential path traversal (user input in file path)", "file_security", "HIGH", (".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".php", ".rb", ".java"),
     re.compile(r"(?i)(readFile|readFileSync|sendFile|open\s*\(|os\.path\.join|path\.join|join\s*\()\s*\(?[^)]{0,160}?(req\.|query|params|body|headers)")),
    ("sqli", "Potential SQL injection (string-built query)", "injection", "HIGH", (".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".php", ".java"),
     re.compile(r"(?i)(\.query|\.execute|\.exec|executeQuery|SELECT|INSERT|UPDATE|DELETE)\s*\(\s*[`'\"]?[^)]{0,160}?(\+|\$\{|%s|\|)\s*[^)]{0,80}?(req\.|query|params|body|headers|request\.)")),
    ("yaml-pickle", "Unsafe deserialization (yaml.load / pickle.loads)", "injection", "HIGH", (".py",),
     re.compile(r"(?i)\b(yaml\.load|pickle\.loads|shelve\.open)\s*\(")),
    ("debug-endpoint", "Debug endpoint exposed", "configuration", "MEDIUM", (".py", ".js", ".ts", ".jsx"),
     re.compile(r"(?i)(@\w+\.(get|post|route)\(\s*['\"]/?(debug|api/debug)|app\.(get|post)\(\s*['\"]/?(debug|api/debug)|\.route\(['\"]/debug)")),
    ("unsafe-cors", "Unsafe CORS configuration (wildcard)", "configuration", "MEDIUM", (".js", ".jsx", ".ts", ".tsx", ".py", ".go"),
     re.compile(r"(?i)(Access-Control-Allow-Origin|allow_origins\s*=\s*\[\s*['\"]\*)")),
    ("hardcoded-secret", "Possible hardcoded secret in source", "secrets", "HIGH", (".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".php", ".java", ".env"),
     re.compile(r"""(?ix)(?:const|let|var|static\s+\w+)?\s*(?:api[_-]?key|apikey|secret[_-]?key|secret|password|passwd|token|access[_-]?key|jwt[_-]?secret)\s*[:=]\s*["'][^"']{12,}["']""")),
    ("insecure-cookie", "Cookie set without security flags", "configuration", "MEDIUM", (".js", ".jsx", ".ts", ".tsx", ".py"),
     re.compile(r"(?i)(setHeader\(\s*['\"]Set-Cookie|set_cookie\s*\(|res\.cookie\s*\()")),
]


def scan_static(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    root = root.resolve()
    try:
        files = list(root.rglob("*"))
    except OSError:
        return []
    for path in files:
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root)
        if any(part in IGNORED for part in rel.parts):
            continue
        if path.suffix.lower() not in TEXT_EXT or path.name in SKIP_FILES:
            continue
        try:
            if path.stat().st_size > 400 * 1024:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for check_id, title, category, severity, exts, pattern in CHECKS:
            if path.suffix.lower() not in exts:
                continue
            for lineno, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append({
                        "title": title,
                        "category": category,
                        "severity": severity,
                        "confidence": 0.6,
                        "source": "static-fallback",
                        "affected_component": str(rel),
                        "affected_file": str(rel),
                        "line_start": lineno,
                        "line_end": lineno,
                        "description": f"{title} - matched in {rel}:{lineno}.\n\nCode:\n```\n{line.strip()[:500]}\n```",
                        "evidence": {"tool": "static-fallback", "rule": check_id, "file": str(rel), "line": lineno, "code_snippet": line.strip()[:500]},
                        "reproduction": {"steps": [f"Review {rel} around line {lineno}"], "tool": "static-fallback"},
                    })
    return findings
