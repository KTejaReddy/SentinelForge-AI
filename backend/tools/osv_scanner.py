"""OSV-Scanner adapter - dependency vulnerability scanning.

Runs OSV-Scanner recursively over the working copy (auto-detects lockfiles:
npm, pip, composer, go.mod, maven, gem, cargo, etc.) and normalizes JSON
output into findings. Requires network access to the OSV API on first use;
if unreachable, the limitation is recorded.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from events import log
from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding, normalize_severity
from utils.process import ProcessSpec, run_process


def _severity_from_cvss(item: dict[str, Any]) -> str:
    sevs = item.get("severity") or []
    for s in sevs:
        try:
            score = float(s.get("score", 0))
        except (TypeError, ValueError):
            continue
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    db = item.get("database_specific", {})
    return normalize_severity(db.get("severity", "MEDIUM"), "MEDIUM")


class OsvScannerAdapter(ToolAdapter):
    name = "osv-scanner"
    display_name = "OSV-Scanner"

    def detect(self) -> bool:
        return shutil.which("osv-scanner") is not None

    def version(self) -> str | None:
        res = run_process(ProcessSpec(cmd=["osv-scanner", "--version"], timeout_s=30))
        line = (res.stdout or res.stderr).splitlines()
        return line[0].split(",")[0] if line else None

    def install_hint(self) -> str:
        return "https://github.com/google/osv-scanner/releases (official binaries) | scoop install osv-scanner"

    LOCKFILES = (
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
        "requirements.txt", "poetry.lock", "Pipfile.lock", "pyproject.toml",
        "go.sum", "Gopkg.lock", "Cargo.lock", "Gemfile.lock", "composer.lock",
        "pom.xml", "build.gradle", "gradle.lockfile", "packages.lock.json", "obj/project.assets.json",
    )

    def _find_lockfiles(self, ctx: ScanContext, limit: int = 20) -> list[Path]:
        found: list[Path] = []
        for name in self.LOCKFILES:
            for p in ctx.working.rglob(name):
                if "node_modules" in p.parts:
                    continue
                found.append(p)
                if len(found) >= limit:
                    return found
        return found

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        lockfiles = self._find_lockfiles(ctx)
        if not lockfiles:
            ctx.add_limitation("OSV-Scanner: no supported lockfiles/manifests found")
            return []
        out_path = ctx.workspace / "artifacts" / "osv.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["osv-scanner", "scan", "source", "--format", "json", "--output", str(out_path)]
        for lf in lockfiles:
            cmd += ["-L", str(lf)]
        res = run_process(ProcessSpec(cmd=cmd, timeout_s=900, cwd=str(ctx.workspace)))
        if res.timed_out:
            ctx.add_limitation("OSV-Scanner timed out (network?) - dependency scan incomplete")
            return []
        if res.exit_code not in (0, 1):  # 1 = vulnerabilities found
            log(ctx.scan_id, f"osv-scanner exited {res.exit_code}: {(res.stderr or res.stdout)[-300:]}")
            ctx.add_limitation("OSV-Scanner failed (may need network access to the OSV API)")
            return []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            ctx.add_limitation("OSV-Scanner produced no parseable output")
            return []

        findings: list[dict[str, Any]] = []
        for result in data.get("results", []):
            source = result.get("source", {})
            for pkg in result.get("packages", []):
                name = (pkg.get("package") or {}).get("name", "?")
                version = (pkg.get("package") or {}).get("version", "?")
                for vuln in pkg.get("vulnerabilities", []):
                    vid = vuln.get("id", "OSV")
                    aliases = vuln.get("aliases") or []
                    findings.append(make_finding(
                        title=f"Vulnerable dependency: {name} ({vid})",
                        category="dependencies",
                        severity=_severity_from_cvss(vuln),
                        confidence=0.9,
                        source="osv-scanner",
                        affected_component=str(source.get("path", "")),
                        affected_file=str(source.get("path", "")),
                        description=(vuln.get("summary") or "")[:300] + (("\n\n" + vuln.get("details", "")[:500]) if vuln.get("details") else ""),
                        why_it_matters="Known-vulnerable dependencies are a common, directly exploitable entry point.",
                        evidence={"tool": "osv-scanner", "id": vid, "aliases": aliases[:5], "package": name, "version": version, "source": source},
                        reproduction={"steps": [f"osv-scanner {source.get('path', ctx.working)}"], "tool": "osv-scanner"},
                        provenance="Confirmed",
                    ))
        return findings
