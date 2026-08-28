"""Build & Runtime engine - install, build, start, health-check.

Runs entirely inside the sandbox. If the app fails to build/start, the
Build Agent may propose a safe fix to the working copy and retry (bounded).
"""
from __future__ import annotations

import time
from typing import Any

from events import log
from services.scan_context import ScanContext
from utils.process import find_free_port
from services.probes.http import probe

INSTALL_TIMEOUT = 900
BUILD_TIMEOUT = 900
START_TIMEOUT = 120
MAX_BUILD_FIX_ATTEMPTS = 2


def build_and_start(ctx: ScanContext) -> dict[str, Any]:
    detection = ctx.detection or {}
    commands = detection.get("commands", {})
    managers = detection.get("package_managers", {}) or {}
    frameworks = detection.get("frameworks", []) or []
    entrypoints = detection.get("entrypoints", []) or []

    build_log_parts: list[str] = []
    attempts = 0

    while attempts < MAX_BUILD_FIX_ATTEMPTS:
        attempts += 1
        ok = _install_and_build(ctx, commands, managers, build_log_parts)
        ctx.build_log = "\n".join(build_log_parts)[-60_000:]
        if ok:
            break
        # Build Agent fix attempt (AI available? then propose minimal fix)
        if attempts >= MAX_BUILD_FIX_ATTEMPTS:
            break
        from agents.build_agent import attempt_build_fix

        if not attempt_build_fix(ctx, ctx.build_log):
            break
        log(ctx.scan_id, "Build Agent applied a fix - retrying build")

    if not ctx.runtime_log:
        ctx.runtime_log = ctx.build_log

    # ---- start the application -------------------------------------------------
    port = _choose_port(ctx)
    start_cmd = _start_command(ctx, port)
    if not start_cmd:
        log(ctx.scan_id, "No start command detected - skipping runtime", level="warn")
        return {"base_url": None, "started": False, "build_log": ctx.build_log[-4000:]}

    log(ctx.scan_id, f"Starting application: {' '.join(start_cmd)} (port {port})")
    try:
        ctx.sandbox.stop()
    except Exception:
        pass
    # In Docker mode, pass HOST=0.0.0.0 so the app is reachable via port mapping
    is_docker = getattr(ctx.sandbox, 'mode', 'local') == 'docker'
    start_env = {"PORT": str(port)}
    if is_docker:
        start_env["HOST"] = "0.0.0.0"
        start_env["HOSTNAME"] = "0.0.0.0"
    try:
        ctx.sandbox.start_server(start_cmd, cwd=ctx.working, env=start_env)
    except Exception as exc:
        log(ctx.scan_id, f"Failed to start server: {exc}", level="warn")
        ctx.add_limitation(f"Could not start application: {exc}")
        return {"base_url": None, "started": False, "build_log": ctx.build_log[-4000:]}

    base_url = f"http://127.0.0.1:{port}"
    health = _wait_healthy(ctx, base_url)
    ctx.runtime_log = ctx.sandbox.server_logs(400)
    if health:
        log(ctx.scan_id, f"Application is up: {base_url} (health: {health})")
        return {"base_url": base_url, "port": port, "started": True, "health": health, "build_log": ctx.build_log[-4000:]}
    log(ctx.scan_id, "Application did not answer health checks", level="warn")
    ctx.add_limitation("Started process but no HTTP response on expected port")
    return {"base_url": base_url, "port": port, "started": False, "health": None, "build_log": ctx.build_log[-4000:]}


def _install_and_build(ctx: ScanContext, commands: dict[str, Any], managers: dict[str, Any], logs: list[str]) -> bool:
    """Install dependencies + build. Returns True when the project is buildable."""
    install_cmd = commands.get("install")
    build_cmd = commands.get("build")
    langs = ctx.detection.get("languages", {}) or {}

    # Python needs a venv? Use pip with --user? Keep plain pip (deterministic).
    try:
        if install_cmd:
            parts = install_cmd.split()
            log(ctx.scan_id, f"Installing dependencies: {' '.join(parts)}")
            res = ctx.sandbox.run(parts, cwd=ctx.working, timeout_s=INSTALL_TIMEOUT)
            logs.append(f"$ {install_cmd}\n{res.stdout[-4000:]}\n{res.stderr[-2000:]}")
            if res.exit_code != 0:
                log(ctx.scan_id, f"Install failed (exit {res.exit_code})", level="warn")
                return False

        if build_cmd:
            parts = build_cmd.split()
            log(ctx.scan_id, f"Building: {' '.join(parts)}")
            res = ctx.sandbox.run(parts, cwd=ctx.working, timeout_s=BUILD_TIMEOUT)
            logs.append(f"$ {build_cmd}\n{res.stdout[-4000:]}\n{res.stderr[-2000:]}")
            if res.exit_code != 0:
                log(ctx.scan_id, f"Build failed (exit {res.exit_code})", level="warn")
                return False
        # Python entrypoints without install step: install requirements.txt implicitly
        if not install_cmd and "python" in langs and (ctx.working / "requirements.txt").exists():
            res = ctx.sandbox.run(["python", "-m", "pip", "install", "-q", "-r", "requirements.txt"], cwd=ctx.working, timeout_s=INSTALL_TIMEOUT)
            if res.exit_code != 0:
                log(ctx.scan_id, "pip install failed (continuing anyway)", level="warn")
        return True
    except Exception as exc:
        logs.append(f"install/build error: {exc}")
        log(ctx.scan_id, f"Install/build error: {exc}", level="warn")
        return False


def _choose_port(ctx: ScanContext) -> int:
    detected = (ctx.detection.get("ports") or []) if ctx.detection else []
    for p in detected:
        try:
            return find_free_port(p)
        except Exception:
            continue
    return find_free_port()


def _start_command(ctx: ScanContext, port: int) -> list[str] | None:
    detection = ctx.detection or {}
    commands = detection.get("commands", {}) or {}
    frameworks = detection.get("frameworks", []) or []
    entrypoints = detection.get("entrypoints", []) or []
    managers = detection.get("package_managers", {}) or {}
    langs = detection.get("languages", {}) or {}
    # In Docker mode, bind to 0.0.0.0 so the app is reachable via port mapping
    is_docker = getattr(ctx.sandbox, 'mode', 'local') == 'docker'
    bind_host = "0.0.0.0" if is_docker else "127.0.0.1"

    start = commands.get("start")
    if start:
        parts = start.split()
        if parts and parts[0] in ("npm", "yarn", "pnpm"):
            return parts + ["--", "--host", bind_host, "--port", str(port)] if "dev" in start or "start" in start else parts
        return parts

    if "fastapi" in frameworks:
        app_module = _find_fastapi_app(ctx.working, entrypoints)
        return ["python", "-m", "uvicorn", app_module, "--host", bind_host, "--port", str(port)]
    if "flask" in frameworks:
        return ["python", "-m", "flask", "run", "--host", bind_host, "--port", str(port)]
    if "django" in frameworks:
        return ["python", "manage.py", "runserver", f"{bind_host}:{port}"]
    if "express" in frameworks or "nestjs" in frameworks or "fastify" in frameworks:
        for e in entrypoints:
            if e.endswith((".js", ".ts", ".mjs", ".cjs")) and not e.endswith(".config.js"):
                return ["node", e]
        for cand in ("server.js", "app.js", "index.js", "src/index.js", "src/server.js"):
            if (ctx.working / cand).exists():
                return ["node", cand]
        if (ctx.working / "package.json").exists():
            return ["npm", "start"]
    if "python" in langs:
        for e in entrypoints:
            if e.endswith(".py") and e != "manage.py":
                return ["python", e]
        if (ctx.working / "app.py").exists():
            return ["python", "app.py"]
        if (ctx.working / "main.py").exists():
            return ["python", "main.py"]
    if "javascript" in langs or "typescript" in langs:
        if (ctx.working / "package.json").exists():
            return ["npm", "start"]
        for cand in ("server.js", "app.js", "index.js"):
            if (ctx.working / cand).exists():
                return ["node", cand]
    if "go" in langs:
        return ["go", "run", "."]
    if "dotnet" in langs:
        return ["dotnet", "run"]
    return None


def _find_fastapi_app(working, entrypoints) -> str:
    for name in ("main.py", "app.py", "server.py"):
        p = working / name
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
            if "FastAPI(" in text or "fastapi" in text:
                for var in ("app", "application", "api"):
                    if f"{var} = FastAPI(" in text:
                        return f"{name[:-3]}:{var}"
                return f"{name[:-3]}:app"
    return "main:app"


def _wait_healthy(ctx: ScanContext, base_url: str) -> str | None:
    deadline = time.time() + START_TIMEOUT
    paths = ["/", "/health", "/healthz", "/api/health"]
    while time.time() < deadline:
        if ctx.cancel_event.is_set():
            return None
        for path in paths:
            try:
                resp = probe("GET", base_url + path, timeout_s=3)
                if resp.status_code < 500:
                    return f"{path} → {resp.status_code}"
            except Exception:
                continue
        time.sleep(1.5)
    return None
