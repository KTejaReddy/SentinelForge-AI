"""ScanContext - the object threaded through every agent, adapter, and step."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from services.sandbox import get_sandbox

SEVERITY_WEIGHT = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}


@dataclass
class ScanContext:
    scan_id: int
    project_id: int
    project_name: str
    workspace: Path
    original: Path
    working: Path
    patched: Path
    options: dict[str, Any] = field(default_factory=dict)
    intensity: str = "standard"
    cancel_event: threading.Event = field(default_factory=threading.Event)

    # Populated over the scan lifecycle:
    detection: dict[str, Any] = field(default_factory=dict)
    route_map: dict[str, Any] = field(default_factory=dict)      # {"/api/x": {methods, auth, ...}}
    api_map: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)        # port, health, process info
    build_log: str = ""
    runtime_log: str = ""
    tool_results: dict[str, Any] = field(default_factory=dict)
    ai_calls: int = 0
    ai_cost_usd: float = 0.0
    ai_tokens: dict[str, int] = field(default_factory=lambda: {"input": 0, "output": 0})
    findings_bank: list[dict[str, Any]] = field(default_factory=list)  # raw findings awaiting normalization
    limitations: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    attack_graph: list[dict[str, Any]] = field(default_factory=list)

    sandbox: Any = None

    def __post_init__(self) -> None:
        self.sandbox = get_sandbox(self.workspace, self.scan_id)

    def enabled(self, option: str) -> bool:
        return bool(self.options.get(option, True))

    def add_limitation(self, message: str) -> None:
        if message not in self.limitations:
            self.limitations.append(message)

    def bump_ai(self, input_tokens: int, output_tokens: int, cost_usd: float) -> None:
        self.ai_calls += 1
        self.ai_tokens["input"] += input_tokens
        self.ai_tokens["output"] += output_tokens
        self.ai_cost_usd += cost_usd

    def add_graph_node(self, node: dict[str, Any]) -> str:
        node_id = f"n{len(self.attack_graph) + 1}"
        node["id"] = node_id
        self.attack_graph.append(node)
        return node_id

    def add_graph_edge(self, source: str, target: str, label: str = "", kind: str = "discovery") -> None:
        edge = {"source": source, "target": target, "label": label, "kind": kind}
        self.attack_graph.append(edge)
