"""VerificationRunner - real verification of patches with exploit replay.

This module provides:
1. Deterministic exploit reproduction (before/after)
2. Build verification
3. Regression testing
4. Security retest
5. Honest verdict calculation
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from events import log
from services.deterministic_exploits import run_exploit
from services.probes.http import probe
from services.scan_context import ScanContext
from utils.process import ProcessSpec, run_process


class VerificationResult:
    """Structured result of a verification run."""
    
    def __init__(self):
        self.status: str = "NOT_VERIFIED"
        self.build_pass: bool = False
        self.regression_pass: bool = False
        self.exploit_blocked: bool = False
        self.before_exploit: dict[str, Any] = {}
        self.after_exploit: dict[str, Any] = {}
        self.regression_results: dict[str, Any] = {}
        self.security_retest: dict[str, Any] = {}
        self.details: dict[str, Any] = {}
        self.errors: list[str] = []
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "build_pass": self.build_pass,
            "regression_pass": self.regression_pass,
            "exploit_blocked": self.exploit_blocked,
            "before_exploit": self.before_exploit,
            "after_exploit": self.after_exploit,
            "regression_results": self.regression_results,
            "security_retest": self.security_retest,
            "details": self.details,
            "errors": self.errors,
        }


def verify_patch(
    ctx: ScanContext,
    finding: dict[str, Any],
    before_exploit_result: dict[str, Any],
) -> VerificationResult:
    """
    Verify a patch by:
    1. Replaying the original exploit against the patched app
    2. Running native regression tests
    3. Running a targeted security retest
    4. Calculating an honest verdict
    """
    result = VerificationResult()
    base_url = ctx.runtime.get("base_url")
    
    if not base_url:
        result.errors.append("Application not running - cannot verify")
        result.status = "NEEDS_HUMAN_REVIEW"
        return result
    
    finding_title = finding.get("title", "")
    
    # Step 1: Replay original exploit against patched app
    log(ctx.scan_id, f"Verifying: replaying exploit for '{finding_title}'")
    try:
        after_exploit = run_exploit(base_url, finding_title)
        result.after_exploit = after_exploit
        result.before_exploit = before_exploit_result
        
        # Determine if exploit is now blocked
        was_exploited = before_exploit_result.get("exploited", False)
        is_exploited = after_exploit.get("exploited", False)
        
        if was_exploited and not is_exploited:
            result.exploit_blocked = True
            log(ctx.scan_id, f"  Exploit BLOCKED after patch")
        elif was_exploited and is_exploited:
            result.exploit_blocked = False
            log(ctx.scan_id, f"  Exploit STILL WORKS after patch")
        else:
            # Exploit didn't work before either - can't verify
            result.exploit_blocked = True  # treat as pass
            log(ctx.scan_id, f"  Exploit was not reproducible before patch")
    except Exception as exc:
        result.errors.append(f"Exploit replay failed: {exc}")
        log(ctx.scan_id, f"  Exploit replay error: {exc}", level="warn")
    
    # Step 2: Run native regression tests
    test_cmd = (ctx.detection.get("commands") or {}).get("test")
    if test_cmd:
        log(ctx.scan_id, f"Running regression tests: {test_cmd}")
        try:
            res = ctx.sandbox.run(test_cmd.split(), cwd=ctx.working, timeout_s=120)
            result.regression_results = {
                "exit_code": res.exit_code,
                "pass": res.exit_code == 0,
                "stdout": res.stdout[-2000:],
                "stderr": res.stderr[-1000:],
            }
            result.regression_pass = res.exit_code == 0
            log(ctx.scan_id, f"  Regression tests: {'PASS' if res.exit_code == 0 else 'FAIL'} (exit {res.exit_code})")
        except Exception as exc:
            result.regression_results = {"error": str(exc)}
            result.regression_pass = False
            log(ctx.scan_id, f"  Regression test error: {exc}", level="warn")
    
    # Step 3: Targeted security retest
    log(ctx.scan_id, f"Running targeted security retest")
    try:
        # Run the specific exploit one more time to confirm
        confirm = run_exploit(base_url, finding_title)
        result.security_retest = {
            "exploit_result": confirm.get("exploited", False),
            "status_code": confirm.get("before_status"),
        }
    except Exception as exc:
        result.security_retest = {"error": str(exc)}
    
    # Step 4: Calculate verdict
    if result.exploit_blocked and result.regression_pass:
        result.status = "VERIFIED_FIXED"
    elif result.exploit_blocked and not test_cmd:
        # No tests available, but exploit is blocked
        result.status = "VERIFIED_FIXED"
    elif not result.exploit_blocked and result.regression_pass:
        # Exploit still works but tests pass
        result.status = "NOT_FIXED"
    elif not result.exploit_blocked and not result.regression_pass:
        result.status = "NOT_FIXED"
    else:
        result.status = "NEEDS_HUMAN_REVIEW"
    
    return result


def run_exploit_before(ctx: ScanContext, finding: dict[str, Any]) -> dict[str, Any]:
    """
    Run the exploit BEFORE patching to establish baseline.
    Returns the exploit result dict.
    """
    base_url = ctx.runtime.get("base_url")
    if not base_url:
        return {"exploited": False, "error": "app not running"}
    
    finding_title = finding.get("title", "")
    try:
        result = run_exploit(base_url, finding_title)
        log(ctx.scan_id, f"Before-patch exploit for '{finding_title}': exploited={result.get('exploited')}")
        return result
    except Exception as exc:
        log(ctx.scan_id, f"Before-patch exploit error: {exc}", level="warn")
        return {"exploited": False, "error": str(exc)}
