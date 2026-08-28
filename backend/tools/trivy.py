"""Trivy adapter - filesystem vulnerability + secret + config scanning.

Trivy needs to pull the vulnerability DB from the network on first run;
if it cannot, the adapter reports the limitation and returns nothing
(covers: dependency scanning degrades without fabricating results).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding, normalize_severity
from utils.process import ProcessSpec, run_process


class TrivyAdapter(ToolAdapter):
    name = "trivy"
    display_name = "Trivy"

    def detect(self) -> bool:
        return shutil.which("trivy") is not None

    def version(self) -> str | None:
        res = run_process(ProcessSpec(cmd=["trivy", "--version"], timeout_s=30))
        return (res.stdout or res.stderr).splitlines()[0] if (res.exit_code == 0) else None

    def install_hint(self) -> str:
        return "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh"

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        out_path = ctx.workspace / "artifacts" / "trivy.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        res = run_process(ProcessSpec(
            cmd=[
                "trivy", "fs", "--scanners", "vuln,secret,config", "--format", "json",
                "--skip-dirs", "node_modules", "--exit-code", "0",
                "--cache-dir", str(ctx.workspace / ".sf-trivy-cache"),
                "-o", str(out_path), str(ctx.working),
            ],
            timeout_s=900,
            cwd=str(ctx.workspace),
        ))
        if res.timed_out:
            ctx.add_limitation("Trivy timed out (likely first-run DB download) - dependency scan incomplete")
            return []
        if res.exit_code != 0:
            ctx.add_limitation("Trivy failed: " + (res.stderr or res.stdout)[-300:])
            return []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            ctx.add_limitation("Trivy produced no parseable output")
            return []

        findings: list[dict[str, Any]] = []
        for target in data.get("Results", []):
            target_name = target.get("Target", "")
            for vuln in target.get("Vulnerabilities", []):
                severity = normalize_severity(vuln.get("Severity", "MEDIUM"))
                pkg = vuln.get("PkgName", "")
                findings.append(make_finding(
                    title=f"Vulnerable dependency: {pkg} ({vuln.get('VulnerabilityID')})",
                    category="dependencies",
                    severity=severity,
                    confidence=0.9,
                    source="trivy",
                    affected_component=target_name,
                    affected_file=target_name,
                    description=(
                        f"{pkg} {vuln.get('InstalledVersion')} is affected by {vuln.get('VulnerabilityID')}. "
                        f"Fixed in {vuln.get('FixedVersion') or 'unknown'}. {vuln.get('Description', '')[:400]}"
                    ),
                    why_it_matters="Known-vulnerable dependencies are a common, directly exploitable entry point.",
                    evidence={"tool": "trivy", "package": pkg, "installed": vuln.get("InstalledVersion"), "fixed": vuln.get("FixedVersion"), "id": vuln.get("VulnerabilityID"), "cvss": vuln.get("CVSS", {})},
                    reproduction={"steps": [f"Run `trivy fs {target_name}`"], "tool": "trivy"},
                    provenance="Confirmed" if vuln.get("SeveritySource") else "Observed",
                ))
            for misconfig in target.get("Misconfigurations", []):
                severity = normalize_severity(misconfig.get("Severity", "MEDIUM"))
                findings.append(make_finding(
                    title=f"Misconfiguration: {misconfig.get('ID')}",
                    category="configuration",
                    severity=severity,
                    confidence=0.8,
                    source="trivy",
                    affected_component=target_name,
                    affected_file=target_name,
                    description=f"{misconfig.get('Title')}: {misconfig.get('Description', '')[:400]}",
                    evidence={"tool": "trivy", "id": misconfig.get("ID"), "avd": misconfig.get("AVDID")},
                    reproduction={"steps": [f"Run `trivy config {target_name}`"], "tool": "trivy"},
                ))
        if not findings:
            ctx.add_limitation("Trivy found no known vulnerabilities (DB may be stale or unreachable)")
        return findings
