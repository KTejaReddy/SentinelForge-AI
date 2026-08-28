"""SQLAlchemy ORM models - one row per real object, JSON blobs for structured state."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base, JsonText


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json_default() -> dict:
    return {}


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="UPLOADED")
    project_type: Mapped[str] = mapped_column(String(64), default="unknown")
    detection: Mapped[dict] = mapped_column(JsonText, default=_json_default)  # JSON
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    status: Mapped[str] = mapped_column(String(32), default="UPLOADED")  # state machine value
    state: Mapped[str] = mapped_column(String(32), default="UPLOADED")
    intensity: Mapped[str] = mapped_column(String(32), default="standard")
    options: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    scores: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    summary: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    workspace_dir: Mapped[str] = mapped_column(String(1024), default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    project: Mapped[Project] = relationship(back_populates="scans")
    steps: Mapped[list["ScanStep"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    agents: Mapped[list["AgentRun"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    tool_runs: Mapped[list["ToolRun"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    patches: Mapped[list["Patch"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    verifications: Mapped[list["VerificationRun"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanStep(Base):
    __tablename__ = "scan_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="PENDING")  # PENDING/RUNNING/DONE/SKIPPED/FAILED
    order: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="steps")


class AgentRun(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    agent: Mapped[str] = mapped_column(String(64))  # e.g. "recon_agent"
    status: Mapped[str] = mapped_column(String(32), default="PENDING")
    summary: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="agents")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    title: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(64))  # auth/authz/injection/xss/...
    severity: Mapped[str] = mapped_column(String(16))  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open/fixed/verified/needs_review/false_positive
    source: Mapped[str] = mapped_column(String(64), default="")  # e.g. "semgrep+ai"
    affected_component: Mapped[str] = mapped_column(String(255), default="")
    affected_file: Mapped[str] = mapped_column(String(1024), default="")
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    why_it_matters: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    reproduction: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    ai_explanation: Mapped[str] = mapped_column(Text, default="")
    recommended_fix: Mapped[str] = mapped_column(Text, default="")
    patch_status: Mapped[str] = mapped_column(String(32), default="none")  # none/pending/applied/verified/failed
    repair_tool: Mapped[str] = mapped_column(String(64), default="")  # DETERMINISTIC_TOOL/AI_PATCH_FALLBACK/etc
    provenance: Mapped[str] = mapped_column(String(32), default="Observed")  # Observed/Inferred/Potential/Confirmed/Verified
    dedup_key: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    evidence_rows: Mapped[list["Evidence"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    tool: Mapped[str] = mapped_column(String(64), default="")
    target: Mapped[str] = mapped_column(String(1024), default="")
    request: Mapped[str] = mapped_column(Text, default="")
    response: Mapped[str] = mapped_column(Text, default="")
    logs: Mapped[str] = mapped_column(Text, default="")
    screenshot: Mapped[str] = mapped_column(String(1024), default="")
    source_file: Mapped[str] = mapped_column(String(1024), default="")
    source_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stack_trace: Mapped[str] = mapped_column(Text, default="")
    reproduction_steps: Mapped[str] = mapped_column(Text, default="")
    patch_diff: Mapped[str] = mapped_column(Text, default="")
    verification_result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    finding: Mapped[Finding] = relationship(back_populates="evidence_rows")


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    tool: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="PENDING")  # RUNNING/DONE/SKIPPED/FAILED/UNAVAILABLE
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_path: Mapped[str] = mapped_column(String(1024), default="")
    summary: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped[Scan] = relationship(back_populates="tool_runs")


class Patch(Base):
    __tablename__ = "patches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending/applied/failed/verified
    diff: Mapped[str] = mapped_column(Text, default="")
    files: Mapped[dict] = mapped_column(JsonText, default=_json_default)  # {file: {before, after}}
    explanation: Mapped[str] = mapped_column(Text, default="")
    tool_source: Mapped[str] = mapped_column(String(64), default="")  # DETERMINISTIC_TOOL/SEMGREP_AUTOFIX/AI_PATCH_FALLBACK/etc
    repair_type: Mapped[str] = mapped_column(String(64), default="")  # command_injection/path_traversal/etc
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped[Scan] = relationship(back_populates="patches")


class VerificationRun(Base):
    __tablename__ = "verification_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    patch_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32))  # FIXED/PARTIALLY_FIXED/NOT_FIXED/NEEDS_HUMAN_REVIEW
    build_pass: Mapped[bool] = mapped_column(default=False)
    regression_pass: Mapped[bool] = mapped_column(default=False)
    exploit_blocked: Mapped[bool] = mapped_column(default=False)
    details: Mapped[dict] = mapped_column(JsonText, default=_json_default)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped[Scan] = relationship(back_populates="verifications")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    report_type: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(16), default="md")
    path: Mapped[str] = mapped_column(String(1024), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)
