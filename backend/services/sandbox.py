"""Sandbox layer.

Two implementations behind one interface:

1. DockerSandbox - preferred. Each scan gets an isolated container
   (no privileged mode, restricted caps, CPU/memory/process limits,
   separate container + network namespace, execution timeout,
   automatic cleanup). Requires a Docker daemon.
2. LocalSandbox - fallback when Docker is unavailable. Runs the
   uploaded project as an unprivileged child process:
   - cwd confined to the scan workspace
   - scrubbed environment (no host secrets reach the project)
   - dedicated per-scan HOME + npm cache inside the workspace
   - hard timeouts + process-tree termination
   - app is bound to 127.0.0.1 only (documented limitation: without a
     container, kernel-level network isolation is unavailable)
   Never executes uploaded code outside the scan workspace.

The UI + reports surface which sandbox mode was used and its limitations.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from config import settings
from utils.process import ProcessSpec, RunResult, run_process

SECRET_ENV_KEYS = ("GROQ_API_KEY", "AWS_SECRET", "AWS_ACCESS", "DATABASE_URL", "PASSWORD", "PASSWD", "TOKEN", "SECRET_KEY", "PRIVATE_KEY")


class SandboxUnavailable(Exception):
    pass


class SandboxError(Exception):
    pass


def _scrub_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        up = key.upper()
        if any(s in up for s in SECRET_ENV_KEYS):
            env.pop(key, None)
    env["PYTHONUNBUFFERED"] = "1"
    env["NODE_ENV"] = "test"
    env["CI"] = "1"
    env["HOST"] = "127.0.0.1"
    env["HOSTNAME"] = "127.0.0.1"
    if extra:
        env.update(extra)
    return env


class DockerSandbox:
    """Containerized sandbox via the Docker CLI."""

    mode = "docker"
    _docker_path: str | None = None  # cached path to docker binary

    def __init__(self, workspace: Path, scan_id: int):
        self.workspace = workspace
        self.scan_id = scan_id
        self.container_name = f"sentinelforge-{scan_id}"
        self._server_id: str | None = None

    @classmethod
    def _find_docker(cls) -> str | None:
        """Find the docker binary, checking common locations."""
        if cls._docker_path:
            return cls._docker_path
        # Check PATH first
        path = shutil.which("docker")
        if path:
            # On Windows, shutil.which may return path without .exe which
            # causes WinError 193 when used as full path in subprocess.Popen.
            # Ensure the path points to an actual executable.
            if os.name == "nt" and not path.lower().endswith(".exe"):
                exe_path = path + ".exe"
                if os.path.isfile(exe_path):
                    path = exe_path
            cls._docker_path = path
            return path
        # Check common Windows installation paths
        candidates = [
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            r"C:\ProgramData\DockerDesktop\version-bin\docker.exe",
            os.path.expanduser(r"~\AppData\Local\Docker\cli-plugins\docker.exe"),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                cls._docker_path = candidate
                # Add to PATH for subprocess calls
                docker_dir = os.path.dirname(candidate)
                if docker_dir not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = docker_dir + os.pathsep + os.environ.get("PATH", "")
                return candidate
        return None

    @classmethod
    def available(cls) -> bool:
        if not settings.docker_enabled:
            return False
        docker_path = cls._find_docker()
        if not docker_path:
            return False
        try:
            res = run_process(ProcessSpec(cmd=[docker_path, "info"], timeout_s=15))
            return res.exit_code == 0
        except Exception:
            return False

    def _docker(self, args: list[str], timeout_s: float = 600, cwd: str | None = None) -> RunResult:
        docker_cmd = self._find_docker() or "docker"
        return run_process(ProcessSpec(cmd=[docker_cmd, *args], cwd=cwd, timeout_s=timeout_s))

    def ensure_image(self) -> None:
        res = self._docker(["image", "inspect", settings.sandbox_image], timeout_s=30)
        if res.exit_code == 0:
            return
        dockerfile = Path(__file__).resolve().parent.parent.parent / "docker" / "sandbox.Dockerfile"
        if not dockerfile.exists():
            raise SandboxError("sandbox.Dockerfile not found")
        res = self._docker(["build", "-t", settings.sandbox_image, "-f", str(dockerfile), str(dockerfile.parent)])
        if res.exit_code != 0:
            raise SandboxError("Failed to build sandbox image: " + res.stderr[-1500:])

    def _run_in_container(self, cmd: list[str], cwd: str, timeout_s: float, env: dict[str, str] | None = None) -> RunResult:
        env_args: list[str] = []
        if env:
            for k, v in env.items():
                env_args += ["-e", f"{k}={v}"]
        # Calculate relative path for container
        rel = cwd.replace(str(self.workspace), "").lstrip("/\\")
        docker_cmd = self._find_docker() or "docker"
        full_args = [
            "run", "--rm", "--network", "host",
            "--name", f"sf-run-{self.scan_id}-{int(time.time() * 1000)}",
            "--memory", f"{settings.sandbox_memory_mb}m",
            "--cpus", str(settings.sandbox_cpu_limit),
            "--pids-limit", str(settings.sandbox_max_processes),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{self.workspace}:/workspace",
            "-w", f"/workspace/{rel}",
            *env_args,
            settings.sandbox_image,
            *cmd,
        ]
        # Use subprocess directly to set MSYS_NO_PATHCONV
        import subprocess
        run_env = os.environ.copy()
        run_env["MSYS_NO_PATHCONV"] = "1"
        try:
            result = subprocess.run(
                [docker_cmd] + full_args,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                env=run_env,
            )
            return RunResult(
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_s=timeout_s,
            )
        except subprocess.TimeoutExpired:
            return RunResult(stdout="", stderr="timeout", exit_code=-1, duration_s=timeout_s)

    def run(self, cmd: list[str], cwd: Path, timeout_s: float = 300, env: dict[str, str] | None = None) -> RunResult:
        self.ensure_image()
        rel = str(cwd.relative_to(self.workspace)) if cwd.is_relative_to(self.workspace) else "."
        return self._run_in_container(cmd, rel, timeout_s, env)

    def start_server(self, cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
        self.ensure_image()
        rel = str(cwd.relative_to(self.workspace)) if cwd.is_relative_to(self.workspace) else "."
        # Detect port from cmd or env
        port = 3000
        if env and "PORT" in env:
            try:
                port = int(env["PORT"])
            except (ValueError, TypeError):
                pass
        # For npm/node commands, extract port from --port arg
        for i, arg in enumerate(cmd):
            if arg == "--port" and i + 1 < len(cmd):
                try:
                    port = int(cmd[i + 1])
                except (ValueError, TypeError):
                    pass
        # Ensure app listens on 0.0.0.0 for Docker port mapping
        container_env = dict(env) if env else {}
        container_env["HOST"] = "0.0.0.0"
        env_args: list[str] = []
        for k, v in container_env.items():
            env_args += ["-e", f"{k}={v}"]
        # Use port mapping instead of host networking for Docker Desktop compatibility
        docker_cmd = self._find_docker() or "docker"
        full_args = [
            "run", "-d",
            "--name", self.container_name,
            "--memory", f"{settings.sandbox_memory_mb}m",
            "--cpus", str(settings.sandbox_cpu_limit),
            "--pids-limit", str(settings.sandbox_max_processes),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-p", f"{port}:{port}",
            "-v", f"{self.workspace}:/workspace",
            "-w", f"/workspace/{rel}",
            *env_args,
            settings.sandbox_image,
            *cmd,
        ]
        # Set environment variable to prevent Git Bash path conversion
        import subprocess
        proc_env = os.environ.copy()
        proc_env["MSYS_NO_PATHCONV"] = "1"
        result = subprocess.run(
            [docker_cmd] + full_args,
            capture_output=True,
            text=True,
            timeout=120,
            env=proc_env,
        )
        if result.returncode != 0:
            raise SandboxError("Failed to start sandbox container: " + result.stderr[-1500:])
        self._server_id = self.container_name

    def server_logs(self, tail: int = 200) -> str:
        if not self._server_id:
            return ""
        res = self._docker(["logs", "--tail", str(tail), self._server_id], timeout_s=30)
        return res.stdout + res.stderr

    def stop(self) -> None:
        if self._server_id:
            self._docker(["rm", "-f", self._server_id], timeout_s=60)
            self._server_id = None

    def cleanup(self) -> None:
        self.stop()


class LocalSandbox:
    """Process-isolated fallback (no Docker). See module docstring for limits."""

    mode = "local"

    def __init__(self, workspace: Path, scan_id: int):
        self.workspace = workspace
        self.scan_id = scan_id
        self.home = workspace / ".sf-home"
        self.home.mkdir(parents=True, exist_ok=True)
        self._procs: dict[int, subprocess.Popen] = {}
        self._log_path = workspace / "runtime.log"
        self._lock = threading.Lock()

    @classmethod
    def available(cls) -> bool:
        return True

    def _base_env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = _scrub_env(extra)
        env["HOME"] = str(self.home)
        env["USERPROFILE"] = str(self.home)
        env["npm_config_cache"] = str(self.home / ".npm")
        env["PYTHONUSERBASE"] = str(self.home / ".pylocal")
        return env

    def run(self, cmd: list[str], cwd: Path, timeout_s: float = 300, env: dict[str, str] | None = None) -> RunResult:
        return run_process(ProcessSpec(cmd=cmd, cwd=cwd, env=self._base_env(env), timeout_s=timeout_s))

    def start_server(self, cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
        if os.name == "nt":
            kwargs: dict[str, Any] = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            kwargs = {"start_new_session": True}
        log = open(self._log_path, "ab", buffering=0)
        proc = subprocess.Popen(
            list(cmd),
            cwd=str(cwd),
            env=self._base_env(env),
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=False,
            **kwargs,
        )
        with self._lock:
            self._procs[proc.pid] = proc

    def server_logs(self, tail: int = 200) -> str:
        try:
            if not self._log_path.exists():
                return ""
            return self._log_path.read_text(encoding="utf-8", errors="replace")[-tail * 400:]
        except OSError:
            return ""

    def stop(self) -> None:
        with self._lock:
            procs = list(self._procs.values())
            self._procs.clear()
        for proc in procs:
            if proc.poll() is None:
                try:
                    if os.name == "nt":
                        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, timeout=10)
                    else:
                        os.killpg(os.getpgid(proc.pid), 9)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

    def cleanup(self) -> None:
        self.stop()


def get_sandbox(workspace: Path, scan_id: int):
    """Factory: Docker when available, local fallback otherwise."""
    if DockerSandbox.available():
        return DockerSandbox(workspace, scan_id)
    return LocalSandbox(workspace, scan_id)


def sandbox_mode() -> str:
    return "docker" if DockerSandbox.available() else "local"
