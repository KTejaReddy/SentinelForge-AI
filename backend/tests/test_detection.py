"""Tests for multi-language project detection."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.project_detector import detect_project  # noqa: E402


def _project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "proj"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


def test_detect_node_express(tmp_path: Path) -> None:
    root = _project(tmp_path, {
        "package.json": '{"name":"x","scripts":{"start":"node server.js","test":"jest"},"dependencies":{"express":"^4.19.0"}}',
        "server.js": "const express = require('express'); const app = express(); app.get('/api/health', (q,r)=>r.json({})); app.listen(3000);",
    })
    det = detect_project(root)
    assert "express" in det["frameworks"]
    assert "npm" in det["package_managers"]
    assert det["commands"]["start"] == "node server.js"
    assert 3000 in det["ports"]
    assert det["project_type"] == "webapp"


def test_detect_fastapi(tmp_path: Path) -> None:
    root = _project(tmp_path, {
        "main.py": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(): pass",
        "requirements.txt": "fastapi\nuvicorn",
    })
    det = detect_project(root)
    assert "fastapi" in det["frameworks"]
    assert "pip" in det["package_managers"]
    assert "python" in det["languages"]
    assert 8000 in det["ports"]


def test_detect_django_flask_golang(tmp_path: Path) -> None:
    root = _project(tmp_path, {
        "manage.py": "if __name__ == '__main__': pass",
        "app.py": "from flask import Flask\napp = Flask(__name__)\n@app.route('/')\ndef home(): return 'x'",
    })
    det = detect_project(root)
    assert "django" in det["frameworks"] or "flask" in det["frameworks"]

    go = _project(tmp_path, {"go.mod": "module example.com/x\n\ngo 1.21", "main.go": "package main"})
    det_go = detect_project(go)
    assert "go" in det_go["languages"]
    assert det_go["commands"]["build"] == "go build ./..."


def test_route_discovery(tmp_path: Path) -> None:
    from services.probes.http import discover_routes

    root = _project(tmp_path, {
        "server.js": (
            "const app = require('express')();\n"
            "app.get('/api/users', (q,r)=>r.json([]));\n"
            "app.post('/api/login', (q,r)=>r.json({}));\n"
            "router.get('/api/items/:id', (q,r)=>r.json({}));\n"
        ),
    })
    routes = discover_routes(root)
    paths = {r["path"] for r in routes}
    assert "/api/users" in paths
    assert "/api/login" in paths
    assert any("items" in r["path"] and ("{id}" in r["path"] or ":id" in r["path"]) for r in routes)
