"""Built-in secrets scanner - deterministic regex-based detection.

Used as the authoritative "Secrets Detection" step and as the fallback
when Gitleaks is unavailable. Reports real matches only; every finding
points at the exact file/line and includes the matched pattern family.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

IGNORED = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".next", "target", "coverage", ".sf-home"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2", ".ttf", ".map", ".lock", ".svg"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Gemfile.lock", "composer.lock", "go.sum", "Cargo.lock"}

PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("AWS Access Key", "secrets", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key", "secrets", re.compile(r"(?i)\baws(.{0,20})?(secret|secret_access|access_key_secret)(.{0,20})?['\"\s:=]+([A-Za-z0-9/+=]{40})\b")),
    ("GitHub Token (classic)", "secrets", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub Fine-Grained PAT", "secrets", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("OpenAI API Key", "secrets", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Slack Token", "secrets", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API Key", "secrets", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe Key", "secrets", re.compile(r"\b(sk|pk)_(live|test)_[0-9a-zA-Z]{10,}\b")),
    ("Private Key Block", "secrets", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----")),
    ("Generic API Key Assignment", "secrets", re.compile(r"""(?ix)(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-\./+=]{16,})["']""")),
    ("JWT Secret", "secrets", re.compile(r"""(?ix)(jwt[_-]?secret|token[_-]?secret)\s*[:=]\s*["'][^"']{16,}["']""")),
    ("Password in Config", "secrets", re.compile(r"""(?ix)(password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{6,}["']""")),
    ("Database Connection String", "secrets", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"@]+:[^\s'\"@]+@")),
    ("npm Token", "secrets", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("Firebase Key", "secrets", re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b")),
]


def scan_secrets(root: Path, max_bytes_per_file: int = 512 * 1024) -> list[dict[str, Any]]:
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
        if path.suffix.lower() in SKIP_EXT or path.name in SKIP_FILES:
            continue
        try:
            if path.stat().st_size > max_bytes_per_file:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for family, category, pattern in PATTERNS:
            for m in pattern.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                snippet = text[max(0, m.start() - 40):m.end() + 40].replace("\n", " ")
                # Skip obvious demo/fake values to reduce noise? No - report real matches,
                # the AI can classify. But drop short generic matches that are likely ids.
                findings.append({
                    "title": f"Secret pattern: {family}",
                    "category": "secrets",
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "source": "secret-scanner",
                    "affected_component": str(rel),
                    "affected_file": str(rel),
                    "line_start": line,
                    "line_end": line,
                    "description": f"Detected a likely {family} in {rel} (line {line}). Matched pattern family: {family}.",
                    "evidence": {"tool": "secret-scanner", "pattern": family, "file": str(rel), "line": line, "snippet": snippet[:200]},
                    "reproduction": {"steps": [f"Inspect {rel} around line {line}"], "tool": "secret-scanner"},
                })
    # dedup identical file+line+family
    seen: set[tuple[str, str, int]] = set()
    out = []
    for f in findings:
        key = (f["evidence"]["pattern"], f["affected_file"], f["line_start"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
