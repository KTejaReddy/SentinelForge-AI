"""Project-native test runner adapter.

Runs the project's own tests inside the sandbox (project code execution
is always sandboxed) and records the result as regression evidence.
"""
from __future__ import annotations

import re

from events import log
from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding
from utils.process import ProcessSpec

TEST_CMD_HINTS = {
    "npm": ["npm", "test", "--", "--runInBand"],
    "pytest": ["python", "-m", "pytest", "-q", "--no-header"],
    "pip": ["python", "-m", "pytest", "-q", "--no-header"],
    "maven": ["mvn", "-q", "test"],
    "gradle": ["gradle", "test", "--console=plain"],
    "go": ["go", "test", "./..."],
    "composer": ["vendor/bin/phpunit"],
    "bundler": ["bundle", "exec", "rspec"],
    "dotnet": ["dotnet", "test"],
    "cargo": ["cargo", "test"],
}


class NativeTestAdapter(ToolAdapter):
    name = "native_tests"
    display_name = "Native Tests"

    def detect(self) -> bool:
        return True

    def install_hint(self) -> str:
        return ""

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        detection = ctx.detection
        commands = detection.get("commands", {})
        test_cmd = commands.get("test")
        findings: list[dict[str, Any]] = []

        if test_cmd:
            cmd = test_cmd.split()
            if cmd[0] == "npm" and len(cmd) == 1:
                cmd = ["npm", "test", "--", "--runInBand"]
        else:
            for manager, hint in TEST_CMD_HINTS.items():
                if manager in detection.get("package_managers", {}):
                    cmd = hint
                    break
            else:
                ctx.add_limitation("No project-native test command detected")
                ctx.tool_results["native_tests"] = {"status": "no test command"}
                return findings

        log(ctx.scan_id, f"Running project tests: {' '.join(cmd)}")
        res = ctx.sandbox.run(cmd, cwd=ctx.working, timeout_s=900)
        log_path = ctx.workspace / "artifacts" / "native_tests.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(res.stdout + "\n--- STDERR ---\n" + res.stderr, encoding="utf-8", errors="replace")

        combined = res.stdout + res.stderr
        passed = failed = skipped = 0
        for m in re.finditer(r"(\d+)\s+passed", combined):
            passed += int(m.group(1))
        for m in re.finditer(r"(\d+)\s+failed", combined):
            failed += int(m.group(1))
        for m in re.finditer(r"(\d+)\s+skipped", combined):
            skipped += int(m.group(1))
        if not passed and not failed:
            # Jest/vitest formats
            m = re.search(r"Tests:\s*(\d+)\s+failed", combined)
            if m:
                failed += int(m.group(1))
            m = re.search(r"Tests:\s*(\d+)\s+passed", combined)
            if m:
                passed += int(m.group(1))

        ctx.tool_results["native_tests"] = {
            "command": " ".join(cmd),
            "exit_code": res.exit_code,
            "passed": passed, "failed": failed, "skipped": skipped,
            "log": str(log_path),
        }
        if res.exit_code == 0:
            log(ctx.scan_id, f"Project tests: {passed} passed, {failed} failed")
        else:
            log(ctx.scan_id, f"Project tests FAILED ({failed} failed / {passed} passed)", level="warn")
            tail = combined[-1200:]
            findings.append(make_finding(
                title=f"Project test suite failed ({failed} failing)",
                category="reliability",
                severity="MEDIUM" if failed > 0 else "LOW",
                confidence=0.95,
                source="native-tests",
                description=f"`{' '.join(cmd)}` exited {res.exit_code} with {failed} failing test(s).",
                evidence={"tool": "native-tests", "command": " ".join(cmd), "exit_code": res.exit_code, "output_tail": tail},
                reproduction={"steps": [f"Run `{' '.join(cmd)}` in the project root"], "tool": "native-tests"},
            ))
        return findings
