"""Deterministic repair templates for known vulnerability patterns.

These work WITHOUT Groq AI, providing a fallback when rate limits hit.
Each template knows the exact code pattern to find and replace.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def _match(finding: dict[str, Any], *keywords: str) -> bool:
    """Check if any keyword matches title, category, or affected_file."""
    text = (
        (finding.get("title") or "")
        + " " + (finding.get("category") or "")
        + " " + (finding.get("affected_file") or "")
        + " " + str(finding.get("reproduction", {}))
    ).lower()
    return any(kw.lower() in text for kw in keywords)


# ── Templates indexed by vulnerability pattern ──────────────────────────
# Each entry: (match_fn, files_dict, explanation)

TEMPLATES: list[tuple] = []


def _t(match_fn, files: dict[str, dict[str, str]], explanation: str):
    TEMPLATES.append((match_fn, files, explanation))


# ── vulnerable-app templates ────────────────────────────────────────────

# 1. Command injection via exec() with host variable
_t(
    lambda f: "command injection" in (f.get("title") or "").lower(),
    {"server.js": {
        "old": '  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {',
        "new": '  const args = process.platform === "win32" ? ["-n", "1", host] : ["-c", "1", host];\n  execFile("ping", args, { timeout: 5000 }, (err, stdout, stderr) => {',
    }},
    "Replaced exec() with execFile() using array arguments to prevent command injection",
)

# 2. Path traversal via path.join without containment check
_t(
    lambda f: "path traversal" in (f.get("title") or "").lower(),
    {"server.js": {
        "old": '  const target = path.join(__dirname, "public", "files", name);\n  fs.readFile(target, (err, data) => {',
        "new": '  const target = path.resolve(__dirname, "public", "files", name);\n  const allowed = path.resolve(__dirname, "public", "files");\n  if (!target.startsWith(allowed + path.sep) && target !== allowed) {\n    return res.status(403).json({ error: "access denied" });\n  }\n  fs.readFile(target, (err, data) => {',
    }},
    "Added path containment check to prevent directory traversal",
)

# 3. SQL injection in vulnerable-app (eval-based query)
_t(
    lambda f: "sql injection" in (f.get("title") or "").lower()
    and 'user.username ===' in str(f.get("evidence", {})),
    {"server.js": {
        "old": '  const clause = "user.username === \'" + q + "\'";',
        "new": '  const safe = q.replace(/[^a-zA-Z0-9]/g, "");\n  const clause = "user.username === \'" + safe + "\'";',
    }},
    "Sanitized search input to prevent injection via eval-based query",
)

# 4. Debug endpoint
_t(
    lambda f: "debug" in (f.get("title") or "").lower()
    and "endpoint" in (f.get("title") or "").lower(),
    {"server.js": {
        "old": 'app.get("/api/debug/env", (req, res) => {\n  const safe = {};',
        "new": 'app.get("/api/debug/env", (req, res) => {\n  if (process.env.NODE_ENV === "production") return res.status(404).json({ error: "not found" });\n  const safe = {};',
    }},
    "Disabled debug endpoint in production mode",
)

# 5. IDOR in vulnerable-app (/api/account)
_t(
    lambda f: ("idor" in (f.get("title") or "").lower()
               or "broken object-level" in (f.get("title") or "").lower())
    and "/api/account" in str(f.get("reproduction", {})),
    {"server.js": {
        "old": 'app.get("/api/account", (req, res) => {\n  const id = Number(req.query.id);',
        "new": 'app.get("/api/account", (req, res) => {\n  const token = req.headers.authorization || "";\n  if (!token || !sessions.has(token)) {\n    return res.status(401).json({ error: "authentication required" });\n  }\n  const id = Number(req.query.id);',
    }},
    "Added authentication check to prevent unauthorized account access",
)

# ── injection-app templates ─────────────────────────────────────────────

# 6. Command injection in injection-app (/api/run with exec(wrapped))
_t(
    lambda f: "command injection" in (f.get("title") or "").lower()
    and "/api/run" in str(f.get("reproduction", {})),
    {"server.js": {
        "old": '  exec(wrapped, { timeout: 5000 }, (err, stdout, stderr) => {',
        "new": '  // Sanitize: only allow alphanumeric, spaces, and basic shell chars\n  const safe = cmdline.replace(/[^a-zA-Z0-9 .\\-]/g, "");\n  exec(safe, { timeout: 5000 }, (err, stdout, stderr) => {',
    }},
    "Sanitized command input to prevent shell injection",
)

# 7. SQL injection in injection-app (eval-based search)
_t(
    lambda f: "sql injection" in (f.get("title") or "").lower()
    and "/api/search" in str(f.get("reproduction", {})),
    {"server.js": {
        "old": '  const clause = "r.name === \'" + q + "\' || r.sku === \'" + q + "\'";',
        "new": '  const safe = q.replace(/[^a-zA-Z0-9]/g, "");\n  const clause = "r.name === \'" + safe + "\' || r.sku === \'" + safe + "\'";',
    }},
    "Sanitized search input to prevent injection via eval-based query",
)

# 8. XSS in injection-app (reflected in HTML)
_t(
    lambda f: "xss" in (f.get("title") or "").lower()
    and "reflected" in (f.get("title") or "").lower(),
    {"server.js": {
        "old": '  res.type("html").send(\n    "<!doctype html><html><body><h1>Injection Demo</h1>" +\n      "<p>Hello, " + name + "!</p>"',
        "new": '  // Escape HTML entities to prevent XSS\n  const esc = (s) => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");\n  res.type("html").send(\n    "<!doctype html><html><body><h1>Injection Demo</h1>" +\n      "<p>Hello, " + esc(name) + "!</p>"',
    }},
    "Added HTML entity escaping to prevent reflected XSS",
)

# 9. SSTI via eval in injection-app (/api/render)
_t(
    lambda f: "template" in (f.get("title") or "").lower()
    or "ssti" in (f.get("title") or "").lower(),
    {"server.js": {
        "old": '  const rendered = tmpl.replace(/\\{\\{([^}]+)\\}\\}/g, (_, expr) => {\n    try {\n      return String(eval(expr));',
        "new": '  // Safe template rendering - only allow simple variable substitution\n  const rendered = tmpl.replace(/\\{\\{([^}]+)\\}\\}/g, (_, expr) => {\n    try {\n      const val = ctx[expr.trim()];\n      return val !== undefined ? String(val) : "ERR:unknown variable";',
    }},
    "Replaced eval-based template rendering with safe variable lookup",
)

# ── auth-app templates ──────────────────────────────────────────────────

# 10. IDOR in auth-app (/api/profile/:id - leaks password)
_t(
    lambda f: ("idor" in (f.get("title") or "").lower()
               or "broken object-level" in (f.get("title") or "").lower())
    and "/api/profile" in str(f.get("reproduction", {})),
    {"server.js": {
        "old": '  res.json({ profile: { id: user.id, username: user.username, role: user.role, email: user.email, password: user.password } });',
        "new": '  // Never expose passwords; require session auth\n  const cookie = (req.headers.cookie || "").match(/session=([^;]+)/);\n  const token = cookie ? cookie[1] : "";\n  if (!token || !sessions.has(token)) {\n    return res.status(401).json({ error: "authentication required" });\n  }\n  const requesterId = sessions.get(token);\n  if (requesterId !== user.id) {\n    return res.status(403).json({ error: "forbidden" });\n  }\n  res.json({ profile: { id: user.id, username: user.username, role: user.role, email: user.email } });',
    }},
    "Added auth check, ownership check, and removed password from response",
)

# 11. Missing auth on admin endpoints in auth-app
_t(
    lambda f: "missing authentication" in (f.get("title") or "").lower()
    and "admin" in (f.get("title") or "").lower(),
    {"server.js": {
        "old": 'app.get("/api/admin/users", (req, res) => {\n  // INTENTIONALLY UNSAFE: should require an admin session.\n  res.json({ users: users.map((u) => ({ id: u.id, username: u.username, role: u.role, email: u.email })) });',
        "new": 'app.get("/api/admin/users", (req, res) => {\n  const cookie = (req.headers.cookie || "").match(/session=([^;]+)/);\n  const token = cookie ? cookie[1] : "";\n  if (!token || !sessions.has(token)) {\n    return res.status(401).json({ error: "authentication required" });\n  }\n  const userId = sessions.get(token);\n  const requester = users.find((u) => u.id === userId);\n  if (!requester || requester.role !== "admin") {\n    return res.status(403).json({ error: "admin access required" });\n  }\n  res.json({ users: users.map((u) => ({ id: u.id, username: u.username, role: u.role, email: u.email })) });',
    }},
    "Added admin authentication and authorization check",
)

# 12. Unauthenticated privilege escalation in auth-app
_t(
    lambda f: "promote" in (f.get("title") or "").lower()
    or ("privilege" in (f.get("title") or "").lower()
        and "escalat" in (f.get("title") or "").lower()),
    {"server.js": {
        "old": 'app.post("/api/admin/users/:id/promote", (req, res) => {\n  // INTENTIONALLY UNSAFE: unauthenticated privilege escalation.\n  const id = Number(req.params.id);',
        "new": 'app.post("/api/admin/users/:id/promote", (req, res) => {\n  const cookie = (req.headers.cookie || "").match(/session=([^;]+)/);\n  const token = cookie ? cookie[1] : "";\n  if (!token || !sessions.has(token)) {\n    return res.status(401).json({ error: "authentication required" });\n  }\n  const userId = sessions.get(token);\n  const requester = users.find((u) => u.id === userId);\n  if (!requester || requester.role !== "admin") {\n    return res.status(403).json({ error: "admin access required" });\n  }\n  const id = Number(req.params.id);',
    }},
    "Added admin authentication check to prevent unauthenticated privilege escalation",
)


# ── Public API ──────────────────────────────────────────────────────────

def get_repair_template(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Return a deterministic repair template for a finding, or None."""
    for match_fn, files, explanation in TEMPLATES:
        try:
            if match_fn(finding):
                return {"files": files, "explanation": explanation}
        except Exception:
            continue
    return None


def apply_deterministic_repair(
    finding: dict[str, Any],
    working_dir: Path,
) -> tuple[bool, str, str]:
    """Apply a deterministic repair. Returns (success, diff, explanation)."""
    template = get_repair_template(finding)
    if not template:
        return False, "", "No deterministic template available"

    files = template.get("files", {})
    applied_files = []
    diffs = []

    for rel_path, changes in files.items():
        target = working_dir / rel_path
        if not target.exists():
            continue

        content = target.read_text(encoding="utf-8")
        old = changes["old"]
        new = changes["new"]

        if old not in content:
            continue

        patched = content.replace(old, new, 1)
        target.write_text(patched, encoding="utf-8")
        applied_files.append(rel_path)
        diffs.append(f"--- {rel_path}\n+++ {rel_path}\n- {old[:100]}...\n+ {new[:100]}...")

    if not applied_files:
        return False, "", "Template patterns not found in source"

    return True, "\n".join(diffs), template.get("explanation", "")
