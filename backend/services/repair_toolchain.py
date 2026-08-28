"""Repair Toolchain - Deterministic repair tools with labeled sources.

Each repair is labeled with its source:
- DETERMINISTIC_TOOL: Pre-defined repair template
- SEMGREP_AUTOFIX: Semgrep autofix rule
- DEPENDENCY_TOOL: Package manager update
- CONFIGURATION_REPAIR: Configuration fix
- AST_REPAIR: AST-based transformation
- AI_PATCH_FALLBACK: AI-generated patch (fallback only)
- MANUAL_REVIEW: Requires human review
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from events import log


class RepairResult:
    """Structured result of a repair attempt."""
    
    def __init__(self):
        self.success: bool = False
        self.tool_source: str = "UNKNOWN"
        self.diff: str = ""
        self.explanation: str = ""
        self.files_changed: list[str] = []
        self.errors: list[str] = []
        self.repair_type: str = ""  # e.g., "command_injection", "path_traversal"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "tool_source": self.tool_source,
            "diff": self.diff,
            "explanation": self.explanation,
            "files_changed": self.files_changed,
            "errors": self.errors,
            "repair_type": self.repair_type,
        }


def classify_repair_type(finding: dict[str, Any]) -> str:
    """Classify the repair type based on the finding."""
    title = (finding.get("title") or "").lower()
    category = (finding.get("category") or "").lower()
    
    if "command injection" in title or "command" in category:
        return "command_injection"
    elif "path traversal" in title or "file" in category:
        return "path_traversal"
    elif "sql injection" in title or "sqli" in title:
        return "sql_injection"
    elif "xss" in title or "cross-site" in title:
        return "xss"
    elif "idor" in title or "broken object" in title or "authorization" in category:
        return "idor"
    elif "debug" in title or "configuration" in category:
        return "configuration"
    elif "secret" in title or "leak" in title:
        return "secret_exposure"
    elif "template" in title or "ssti" in title:
        return "template_injection"
    else:
        return "unknown"


def get_available_repair_tools() -> dict[str, list[str]]:
    """Return available repair tools grouped by category."""
    return {
        "deterministic": [
            "command_injection_fix",
            "path_traversal_fix",
            "sql_injection_fix",
            "xss_fix",
            "idor_fix",
            "configuration_fix",
            "secret_removal",
            "template_injection_fix",
        ],
        "semgrep_autofix": [
            "semgrep_rule_based_fix",
        ],
        "dependency": [
            "npm_audit_fix",
            "pip_audit_fix",
        ],
        "configuration": [
            "debug_endpoint_disable",
            "security_headers",
            "cors_fix",
        ],
        "ai_fallback": [
            "ai_generated_patch",
        ],
    }


def validate_repair_safety(finding: dict[str, Any], repair_type: str) -> tuple[bool, str]:
    """Validate that a repair is safe to attempt.
    
    Returns (is_safe, reason).
    """
    # Check if the finding has enough information
    if not finding.get("affected_file"):
        return False, "No affected file specified"
    
    if not finding.get("reproduction"):
        return False, "No reproduction steps available"
    
    # Check if the repair type is supported
    available = get_available_repair_tools()
    all_tools = []
    for category in available.values():
        all_tools.extend(category)
    
    # Map repair type to tool name
    tool_map = {
        "command_injection": "command_injection_fix",
        "path_traversal": "path_traversal_fix",
        "sql_injection": "sql_injection_fix",
        "xss": "xss_fix",
        "idor": "idor_fix",
        "configuration": "configuration_fix",
        "secret_exposure": "secret_removal",
        "template_injection": "template_injection_fix",
    }
    
    tool_name = tool_map.get(repair_type, "")
    if tool_name not in all_tools:
        return False, f"Repair type '{repair_type}' not supported by any tool"
    
    return True, f"Repair type '{repair_type}' is supported"


def estimate_repair_confidence(finding: dict[str, Any], repair_type: str) -> float:
    """Estimate confidence that a repair will succeed.
    
    Returns a value between 0.0 and 1.0.
    """
    base_confidence = {
        "command_injection": 0.9,  # Well-understood pattern
        "path_traversal": 0.85,   # Path containment is straightforward
        "sql_injection": 0.7,     # Depends on query construction
        "xss": 0.8,               # Output encoding is standard
        "idor": 0.6,              # Requires understanding auth logic
        "configuration": 0.9,     # Usually simple changes
        "secret_exposure": 0.95,  # Just remove the secret
        "template_injection": 0.75,  # Replace eval with safe lookup
    }
    
    confidence = base_confidence.get(repair_type, 0.5)
    
    # Adjust based on finding confidence
    finding_confidence = finding.get("confidence", 0.5)
    confidence = (confidence + finding_confidence) / 2
    
    return round(confidence, 2)


def get_repair_instructions(finding: dict[str, Any]) -> dict[str, Any]:
    """Generate structured repair instructions for a finding.
    
    This is what the AI should produce - a structured instruction,
    not the actual code.
    """
    repair_type = classify_repair_type(finding)
    confidence = estimate_repair_confidence(finding, repair_type)
    
    return {
        "finding_id": finding.get("db_id"),
        "repair_strategy": f"apply_{repair_type}_fix",
        "repair_type": repair_type,
        "confidence": confidence,
        "target_files": [finding.get("affected_file", "")],
        "target_symbols": [],  # To be filled by AI if needed
        "constraints": [
            "preserve API response format",
            "preserve existing functionality",
            "minimize code changes",
        ],
        "verification_plan": [
            "replay_original_exploit",
            "run_native_tests",
            "run_security_retest",
        ],
    }
