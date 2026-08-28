"""Tool registry - availability detection for the UI and install hints."""
from __future__ import annotations

from typing import Any

from schemas import ToolStatusOut


def _adapters() -> list[Any]:
    from tools.semgrep import SemgrepAdapter
    from tools.trivy import TrivyAdapter
    from tools.gitleaks import GitleaksAdapter
    from tools.zap import ZapAdapter
    from tools.nuclei import NucleiAdapter
    from tools.ffuf import FfufAdapter
    from tools.playwright_probe import PlaywrightProbeAdapter
    from tools.bandit import BanditAdapter
    from tools.osv_scanner import OsvScannerAdapter

    return [
        SemgrepAdapter(), TrivyAdapter(), GitleaksAdapter(), ZapAdapter(),
        NucleiAdapter(), FfufAdapter(), PlaywrightProbeAdapter(),
        BanditAdapter(), OsvScannerAdapter(),
    ]


def list_tools() -> list[ToolStatusOut]:
    out = []
    for adapter in _adapters():
        try:
            available = adapter.detect()
            version = adapter.version() if available else None
        except Exception:
            available, version = False, None
        out.append(ToolStatusOut(name=adapter.display_name, available=available, version=version, install_hint=adapter.install_hint()))
    # built-ins are always available
    out.append(ToolStatusOut(name="Dynamic Probes (built-in)", available=True, version="bundled", install_hint=""))
    out.append(ToolStatusOut(name="Secrets Scanner (built-in)", available=True, version="bundled", install_hint=""))
    out.append(ToolStatusOut(name="Fuzzing (built-in)", available=True, version="bundled", install_hint=""))
    out.append(ToolStatusOut(name="Native Test Runner", available=True, version="bundled", install_hint=""))
    return out
