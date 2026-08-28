"""ffuf adapter - controlled endpoint/path discovery against the sandbox.

Bounded: rate limit 20 req/s, 10 threads, 5s timeout, fixed built-in
wordlist, loopback target only.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding
from utils.process import ProcessSpec, run_process

WORDLIST = Path(__file__).parent / "wordlists" / "paths.txt"


class FfufAdapter(ToolAdapter):
    name = "ffuf"
    display_name = "ffuf"

    def detect(self) -> bool:
        return shutil.which("ffuf") is not None

    def version(self) -> str | None:
        res = run_process(ProcessSpec(cmd=["ffuf", "-V"], timeout_s=30))
        return (res.stdout or res.stderr).splitlines()[0].strip() if res.exit_code == 0 else None

    def install_hint(self) -> str:
        return "go install github.com/ffuf/ffuf/v2@latest  |  https://github.com/ffuf/ffuf/releases"

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        base_url = ctx.runtime.get("base_url")
        if not base_url:
            ctx.add_limitation("ffuf skipped: application did not start")
            return []
        if not WORDLIST.exists():
            ctx.add_limitation("ffuf wordlist missing")
            return []
        out_path = ctx.workspace / "artifacts" / "ffuf.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        res = run_process(ProcessSpec(
            cmd=[
                "ffuf", "-w", str(WORDLIST), "-u", base_url.rstrip("/") + "/FUZZ",
                "-mc", "200,201,204,301,302,307,308", "-fc", "404",
                "-rate", "20", "-t", "10", "-timeout", "5", "-s",
                "-of", "json", "-o", str(out_path),
            ],
            timeout_s=600,
            cwd=str(ctx.workspace),
        ))
        findings: list[dict[str, Any]] = []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            ctx.add_limitation("ffuf produced no parseable output")
            return findings
        results = data.get("results", [])
        found: dict[str, dict] = {}
        for r in results:
            path = r.get("input", {}).get("FUZZ", "")
            if path in found:
                continue
            found[path] = r
        if found:
            ctx.tool_results["ffuf"] = {"discovered": sorted(found.keys())}
            # Report discovered non-standard paths once as an informational finding.
            findings.append(make_finding(
                title=f"Discovered {len(found)} additional endpoint(s) via content discovery",
                category="web_security",
                severity="LOW", confidence=0.9, source="ffuf",
                affected_component=base_url,
                description="Endpoints found by controlled path fuzzing (real responses): " + ", ".join(sorted(found.keys())[:40]),
                evidence={"tool": "ffuf", "discovered": sorted(found.keys()), "target": base_url},
                reproduction={"steps": ["ffuf -w paths.txt -u " + base_url + "/FUZZ -mc 200,201,204,301,302"], "tool": "ffuf"},
            ))
        return findings
