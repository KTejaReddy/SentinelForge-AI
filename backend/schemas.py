"""Pydantic schemas - API request/response contracts."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# --- Projects -------------------------------------------------------------

class ProjectOut(BaseModel):
    id: int
    name: str
    filename: str
    sha256: str
    size_bytes: int
    status: str
    project_type: str
    detection: dict[str, Any] = {}
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class ScanOptions(BaseModel):
    security_testing: bool = True
    bug_hunting: bool = True
    static_analysis: bool = True
    dependency_analysis: bool = True
    secrets_detection: bool = True
    dynamic_testing: bool = True
    browser_testing: bool = True
    fuzzing: bool = True
    automatic_repair: bool = True
    verification: bool = True
    intensity: str = "standard"  # standard | aggressive | maximum_safe


class ScanCreate(BaseModel):
    project_id: int
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanStepOut(BaseModel):
    id: int
    name: str
    status: str
    order: int
    detail: str = ""
    result: dict[str, Any] | list[Any] = {}
    started_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}


class EvidenceOut(BaseModel):
    id: int
    tool: str
    target: str
    request: str
    response: str
    logs: str
    screenshot: str
    source_file: str
    source_line: int | None
    stack_trace: str
    reproduction_steps: str
    patch_diff: str
    verification_result: str

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: int
    scan_id: int
    title: str
    category: str
    severity: str
    confidence: float
    status: str
    source: str
    affected_component: str
    affected_file: str
    line_start: int | None
    line_end: int | None
    description: str
    why_it_matters: str
    evidence: dict[str, Any] = {}
    reproduction: dict[str, Any] = {}
    root_cause: str
    ai_explanation: str
    recommended_fix: str
    patch_status: str
    provenance: str
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class PatchOut(BaseModel):
    id: int
    scan_id: int
    finding_id: int | None
    status: str
    diff: str
    files: dict[str, Any] = {}
    explanation: str
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class VerificationOut(BaseModel):
    id: int
    scan_id: int
    patch_id: int | None
    finding_id: int | None
    status: str
    build_pass: bool
    regression_pass: bool
    exploit_blocked: bool
    details: dict[str, Any] = {}
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    project_id: int
    status: str
    state: str
    intensity: str
    options: dict[str, Any] = {}
    progress: float
    scores: dict[str, Any] = {}
    summary: dict[str, Any] = {}
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class ScanDetailOut(ScanOut):
    steps: list[ScanStepOut] = []
    findings: list[FindingOut] = []


class ToolStatusOut(BaseModel):
    name: str
    available: bool
    version: str | None = None
    install_hint: str = ""


class GroqTestIn(BaseModel):
    api_key: str = ""
    model: str = ""
    base_url: str = ""


class GroqTestOut(BaseModel):
    ok: bool
    message: str
    model: str = ""
    latency_ms: int = 0


class GroqSettingsIn(BaseModel):
    api_key: str = ""
    model: str = ""
    max_tokens: int = 4096
    temperature: float = 0.2


class AiStatusOut(BaseModel):
    configured: bool
    model: str = ""
    key_hint: str = ""
    cost: dict[str, Any] = {}
