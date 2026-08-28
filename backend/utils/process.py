"""Unified subprocess runner - the only way the platform executes commands.

Guards:
- `shell=False` always (no string interpretation)
- strict timeouts
- full stdout/stderr capture
- process-tree termination on timeout/cancel
- cwd + env control
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Sequence


class ProcessError(Exception):
    pass


@dataclass
class RunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    duration_s: float = 0.0

    @property
    def output(self) -> str:
        return (self.stdout or "") + (("\n" + self.stderr) if self.stderr else "")


@dataclass
class ProcessSpec:
    cmd: Sequence[str]
    cwd: str | os.PathLike | None = None
    env: dict[str, str] | None = None
    timeout_s: float = 120.0
    cancel_event: threading.Event | None = None
    stdin_data: str | None = None
    extra_allowlist: bool = False  # reserved for future allowlist enforcement


def _terminate_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True, timeout=10,
            )
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_process(spec: ProcessSpec) -> RunResult:
    """Run a command and capture output. Never uses a shell."""
    start = time.time()
    cancel = spec.cancel_event
    timeout = spec.timeout_s

    def _poll_cancel() -> None:
        while cancel is not None and not cancel.is_set():
            if proc.poll() is not None:
                return
            time.sleep(0.05)
        if cancel is not None and cancel.is_set():
            _terminate_tree(proc)

    env = dict(os.environ)
    if spec.env:
        env.update(spec.env)
    # Path sanitation for the target project context is handled by the sandbox.

    if os.name == "nt":
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        kwargs = {"creationflags": CREATE_NEW_PROCESS_GROUP}
    else:
        kwargs = {"start_new_session": True}

    cmd = list(spec.cmd)
    if os.name == "nt" and cmd and not os.path.isabs(cmd[0]) and "/" not in cmd[0] and "\\" not in cmd[0]:
        # Windows: bare names like `npm` are npm.cmd - resolve via PATHEXT,
        # preferring real executables over extension-less shims (e.g. Git Bash).
        resolved = _resolve_windows(cmd[0])
        if resolved:
            cmd[0] = resolved

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(spec.cwd) if spec.cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if spec.stdin_data is not None else subprocess.DEVNULL,
            text=True,
            errors="replace",
            **kwargs,
        )
    except FileNotFoundError as exc:
        raise ProcessError(f"Executable not found: {spec.cmd[0]}") from exc
    except OSError as exc:
        raise ProcessError(f"Failed to start {spec.cmd[0]}: {exc}") from exc

    watcher = threading.Thread(target=_poll_cancel, daemon=True) if cancel is not None else None
    if watcher:
        watcher.start()

    timed_out = False
    cancelled = False
    try:
        stdout, stderr = proc.communicate(input=spec.stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_tree(proc)
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except Exception:
            stdout, stderr = "", ""
    except Exception:
        _terminate_tree(proc)
        raise

    if cancel is not None and cancel.is_set() and proc.returncode is None:
        cancelled = True
        _terminate_tree(proc)

    if watcher:
        watcher.join(timeout=2)

    return RunResult(
        exit_code=proc.returncode,
        stdout=stdout or "",
        stderr=stderr or "",
        timed_out=timed_out,
        cancelled=cancelled,
        duration_s=round(time.time() - start, 2),
    )


def _resolve_windows(name: str) -> str | None:
    pathext = [e for e in os.environ.get("PATHEXT", ".EXE;.CMD;.BAT;.COM").split(";") if e]
    for ext in pathext:
        cand = shutil.which(name + ext)
        if cand:
            return cand
    cand = shutil.which(name)
    if cand and not cand.lower().endswith(tuple(e.lower() for e in pathext)):
        # bare match with no executable extension (shell shim) - only accept if it's an .exe/.cmd/.bat/.com
        return None
    return cand


def which_tool(name: str) -> str | None:
    if os.name == "nt":
        return _resolve_windows(name)
    return shutil.which(name)


def find_free_port(preferred: int | None = None) -> int:
    """Find a free TCP port on localhost (used for sandboxed app instances)."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if preferred:
            try:
                sock.bind(("127.0.0.1", preferred))
                return preferred
            except OSError:
                pass
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def python_executable() -> str:
    return sys.executable


def node_executable() -> str:
    return shutil.which("node") or "node"


def npm_executable() -> str:
    return shutil.which("npm") or "npm"
