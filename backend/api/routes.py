"""REST API + SSE endpoints (see §29)."""
from __future__ import annotations

import hashlib
import json
import shutil
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from config import settings, WORKSPACES_DIR, SCANS_DIR, REPORTS_DIR, UPLOADS_DIR
from database import SessionLocal
from events import bus, log
from models import Evidence, Finding, Patch, Project, Report, Scan, ScanStep, Setting, VerificationRun
from schemas import (
    AiStatusOut, FindingOut, GroqSettingsIn, GroqTestIn, GroqTestOut, ProjectOut,
    ScanCreate, ScanDetailOut, ScanOut, ScanStepOut, ToolStatusOut,
)
from security import decrypt_value, encrypt_value, redact_text, validate_zip
from tools.registry import list_tools

router = APIRouter(prefix="/api")

# registry: scan_id -> cancel event (used by POST /stop)
CANCEL_EVENTS: dict[int, threading.Event] = {}


# ---------------------------------------------------------------------------
# Health / tools / settings
# ---------------------------------------------------------------------------


@router.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "sandbox": _sandbox_mode(), "ai_configured": bool(_effective_groq_key())}


@router.get("/tools", response_model=list[ToolStatusOut])
def tools() -> list[ToolStatusOut]:
    return list_tools()


@router.get("/health/tools")
def health_tools() -> dict[str, Any]:
    """Capability matrix: installed toolchain, sandbox mode, runtime, scan limits."""
    import platform
    import sys

    from services.sandbox import DockerSandbox

    docker_ok = DockerSandbox.available()
    if not shutil.which("docker"):
        docker_detail = "not installed (Docker Desktop required on Windows)"
    elif docker_ok:
        docker_detail = "running"
    else:
        docker_detail = "installed but daemon not running (start Docker Desktop)"
    return {
        "status": "ok",
        "sandbox_mode": _sandbox_mode(),
        "docker": {"available": docker_ok, "detail": docker_detail},
        "runtime": {
            "python": sys.version.split()[0],
            "node": _node_version(),
            "os": platform.platform(),
        },
        "tools": [t.model_dump() for t in list_tools()],
        "scan_limits": {
            "max_upload_size_mb": settings.max_upload_size_mb,
            "scan_timeout_seconds": settings.scan_timeout_seconds,
            "max_repair_iterations": settings.max_repair_iterations,
            "max_ai_calls_per_scan": settings.max_ai_calls_per_scan,
            "default_intensity": settings.default_intensity,
        },
    }


def _node_version() -> str:
    try:
        from utils.process import ProcessSpec, run_process

        res = run_process(ProcessSpec(cmd=["node", "--version"], timeout_s=10))
        return res.stdout.strip() if res.exit_code == 0 else "unknown"
    except Exception:
        return "unknown"


@router.get("/settings/groq", response_model=AiStatusOut)
def get_groq_settings() -> AiStatusOut:
    key = _effective_groq_key()
    return AiStatusOut(
        configured=bool(key),
        model=settings.groq_model,
        key_hint=(key[:4] + "…" + key[-4:]) if len(key) > 8 else "",
        cost={"calls": 0, "estimate_usd": 0.0},
    )


@router.post("/settings/groq", response_model=AiStatusOut)
def set_groq_settings(body: GroqSettingsIn) -> AiStatusOut:
    db = SessionLocal()
    try:
        if body.api_key:
            row = db.get(Setting, "groq_api_key_enc")
            if row is None:
                row = Setting(key="groq_api_key_enc", value=encrypt_value(body.api_key))
                db.add(row)
            else:
                row.value = encrypt_value(body.api_key)
        for k, v in (("groq_model", body.model), ("groq_max_tokens", str(body.max_tokens)), ("groq_temperature", str(body.temperature))):
            if v:
                row = db.get(Setting, k)
                if row is None:
                    db.add(Setting(key=k, value=str(v)))
                else:
                    row.value = str(v)
        db.commit()
    finally:
        db.close()
    if body.api_key:
        settings.groq_api_key = body.api_key
    if body.model:
        settings.groq_model = body.model
    return get_groq_settings()


@router.post("/settings/groq/test", response_model=GroqTestOut)
def test_groq(body: GroqTestIn) -> GroqTestOut:
    from services.ai.groq_client import GroqClient

    client = GroqClient(api_key=body.api_key or _effective_groq_key(), model=body.model or settings.groq_model, base_url=body.base_url or settings.groq_base_url)
    ok, message, latency = client.test_connection()
    return GroqTestOut(ok=ok, message=message[:500], model=client.model, latency_ms=latency)


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


@router.post("/projects/upload", response_model=ProjectOut)
async def upload_project(file: UploadFile = File(...)) -> ProjectOut:
    data = await file.read()
    try:
        validate_zip(data, settings.max_upload_size_mb)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    sha256 = hashlib.sha256(data).hexdigest()
    db = SessionLocal()
    try:
        existing = db.query(Project).filter_by(sha256=sha256).first()
        if existing:
            return ProjectOut.model_validate(existing)
        project = Project(
            name=Path(file.filename or "project.zip").stem[:200],
            filename=file.filename or "project.zip",
            sha256=sha256,
            size_bytes=len(data),
            status="UPLOADED",
        )
        db.add(project)
        db.commit()
        db.refresh(project)
        Path(UPLOADS_DIR).mkdir(parents=True, exist_ok=True)
        (Path(UPLOADS_DIR) / f"{project.id}.zip").write_bytes(data)
        return ProjectOut.model_validate(project)
    finally:
        db.close()


@router.get("/projects", response_model=list[ProjectOut])
def list_projects() -> list[ProjectOut]:
    db = SessionLocal()
    try:
        rows = db.query(Project).order_by(Project.created_at.desc()).all()
        return [ProjectOut.model_validate(r) for r in rows]
    finally:
        db.close()


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: int) -> ProjectOut:
    db = SessionLocal()
    try:
        row = db.get(Project, project_id)
        if not row:
            raise HTTPException(status_code=404, detail="project not found")
        return ProjectOut.model_validate(row)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


@router.post("/projects/{project_id}/scan", response_model=ScanOut)
def create_scan(project_id: int, body: ScanCreate) -> ScanOut:
    from orchestrator.scan_orchestrator import run_scan
    from orchestrator.task_queue import submit_scan

    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        if not project:
            raise HTTPException(status_code=404, detail="project not found")
        scan = Scan(
            project_id=project_id,
            state="UPLOADED",
            status="UPLOADED",
            intensity=body.options.intensity,
            options=json.dumps(body.options.model_dump()),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    cancel = threading.Event()
    CANCEL_EVENTS[scan_id] = cancel
    # wire cancel event into the scan thread's ctx via a shared registry
    from orchestrator.task_queue import register_cancel

    register_cancel(scan_id, cancel)
    submit_scan(scan_id, run_scan)

    db = SessionLocal()
    try:
        return ScanOut.model_validate(db.get(Scan, scan_id))
    finally:
        db.close()


@router.get("/scans", response_model=list[ScanOut])
def list_scans() -> list[ScanOut]:
    db = SessionLocal()
    try:
        rows = db.query(Scan).order_by(Scan.created_at.desc()).limit(50).all()
        return [ScanOut.model_validate(r) for r in rows]
    finally:
        db.close()


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: int) -> ScanDetailOut:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")
        detail = ScanDetailOut.model_validate(scan)
        detail.steps = [ScanStepOut.model_validate(s) for s in db.query(ScanStep).filter_by(scan_id=scan_id).order_by(ScanStep.id).all()]
        detail.findings = [FindingOut.model_validate(f) for f in db.query(Finding).filter_by(scan_id=scan_id).order_by(Finding.id).all()]
        return detail
    finally:
        db.close()


@router.post("/scans/{scan_id}/stop")
def stop_scan(scan_id: int) -> dict[str, Any]:
    event = CANCEL_EVENTS.get(scan_id) or _scan_cancel_event(scan_id)
    if event:
        event.set()
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan and scan.state not in ("COMPLETED", "FAILED", "CANCELLED"):
            scan.state = "CANCELLED"
            scan.status = "CANCELLED"
            db.commit()
    finally:
        db.close()
    log(scan_id, "Scan cancellation requested")
    bus.publish(scan_id, {"type": "log", "message": "Scan cancellation requested", "level": "warn"})
    return {"ok": True}


@router.get("/scans/{scan_id}/events")
def scan_events(scan_id: int):
    """Server-Sent Events stream of live scan activity."""

    def gen():
        yield ": connected\n\n"
        yield from bus.subscribe(scan_id)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def scan_findings(scan_id: int) -> list[FindingOut]:
    db = SessionLocal()
    try:
        rows = db.query(Finding).filter_by(scan_id=scan_id).order_by(Finding.id).all()
        return [FindingOut.model_validate(r) for r in rows]
    finally:
        db.close()


@router.get("/scans/{scan_id}/report")
def scan_report(scan_id: int) -> dict[str, Any]:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")
        summary = json.loads(scan.summary) if isinstance(scan.summary, str) else (scan.summary or {})
        scores = json.loads(scan.scores) if isinstance(scan.scores, str) else (scan.scores or {})
        findings = [FindingOut.model_validate(f).model_dump() for f in db.query(Finding).filter_by(scan_id=scan_id).all()]
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "scores": scores,
            "summary": summary,
            "findings": findings,
            "limitations": summary.get("limitations", []),
            "sandbox_mode": summary.get("sandbox_mode", "unknown"),
            "attack_graph": summary.get("attack_graph", []),
        }
    finally:
        db.close()


@router.get("/scans/{scan_id}/attack-graph")
def scan_attack_graph(scan_id: int) -> dict[str, Any]:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404)
        summary = json.loads(scan.summary) if isinstance(scan.summary, str) else (scan.summary or {})
        graph = summary.get("attack_graph") or _build_graph_from_findings(scan_id)
        return {"graph": graph}
    finally:
        db.close()


@router.get("/scans/{scan_id}/download/original")
def download_original(scan_id: int):
    scan = _get_scan_row(scan_id)
    path = Path(SCANS_DIR) / f"scan-{scan_id}" / "original-project.zip"
    if not path.exists():
        upload = Path(UPLOADS_DIR) / f"{scan.project_id}.zip"
        if upload.exists():
            shutil.copy2(upload, path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="original zip not available")
    return FileResponse(path, filename=f"original-project-{scan_id}.zip")


@router.get("/scans/{scan_id}/download/patched")
def download_patched(scan_id: int):
    _get_scan_row(scan_id)
    path = Path(SCANS_DIR) / f"scan-{scan_id}" / "patched-project.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="patched zip not available (scan may be incomplete)")
    return FileResponse(path, filename=f"patched-project-{scan_id}.zip")


@router.get("/scans/{scan_id}/download/reports")
def download_reports(scan_id: int):
    _get_scan_row(scan_id)
    path = Path(SCANS_DIR) / f"scan-{scan_id}" / "reports.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="reports not available")
    return FileResponse(path, filename=f"reports-{scan_id}.zip")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int) -> FindingOut:
    db = SessionLocal()
    try:
        row = db.get(Finding, finding_id)
        if not row:
            raise HTTPException(status_code=404, detail="finding not found")
        return FindingOut.model_validate(row)
    finally:
        db.close()


@router.get("/findings/{finding_id}/detail")
def finding_detail(finding_id: int) -> dict[str, Any]:
    db = SessionLocal()
    try:
        finding = db.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404)
        evidence = [EvidenceOut_row(e) for e in db.query(Evidence).filter_by(finding_id=finding_id).all()]
        patches = [PatchOut_row(p) for p in db.query(Patch).filter_by(finding_id=finding_id).all()]
        verifications = [VerificationOut_row(v) for v in db.query(VerificationRun).filter_by(finding_id=finding_id).order_by(VerificationRun.id).all()]
        return {"finding": FindingOut.model_validate(finding).model_dump(), "evidence": evidence, "patches": patches, "verifications": verifications}
    finally:
        db.close()


@router.post("/findings/{finding_id}/repair")
def repair_finding(finding_id: int) -> dict[str, Any]:
    """Repair a single finding (requires its scan to be completed)."""
    from orchestrator.repair_single import repair_single_finding

    db = SessionLocal()
    try:
        finding = db.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404)
        scan = db.get(Scan, finding.scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")
        if scan.state not in ("COMPLETED", "FAILED", "CANCELLED"):
            raise HTTPException(status_code=409, detail="scan still running")
        scan_id = scan.id
        dedup_key = finding.dedup_key
    finally:
        db.close()
    threading.Thread(target=repair_single_finding, args=(scan_id, finding_id, dedup_key), daemon=True).start()
    return {"ok": True, "message": "repair started"}


@router.post("/findings/{finding_id}/verify")
def verify_finding(finding_id: int) -> dict[str, Any]:
    from orchestrator.repair_single import verify_single_finding

    db = SessionLocal()
    try:
        finding = db.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404)
        scan_id = finding.scan_id
        dedup_key = finding.dedup_key
    finally:
        db.close()
    threading.Thread(target=verify_single_finding, args=(scan_id, finding_id, dedup_key), daemon=True).start()
    return {"ok": True, "message": "verification started"}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


class DemoLoadIn(BaseModel):
    """Optional demo selector body for POST /api/demo/load."""

    name: str = "vulnerable-app"


@router.get("/demo/list")
def list_demos() -> list[dict[str, Any]]:
    """Available built-in demo applications (name + one-line description)."""
    from config import ROOT_DIR

    out: list[dict[str, Any]] = []
    for d in sorted((ROOT_DIR / "demo").iterdir()):
        if not d.is_dir() or not (d / "package.json").exists():
            continue
        desc = ""
        try:
            meta = json.loads((d / "package.json").read_text(encoding="utf-8"))
            desc = meta.get("description", "") or ""
        except (OSError, json.JSONDecodeError):
            pass
        out.append({"name": d.name, "title": _demo_title(d.name), "description": desc})
    return out


@router.post("/demo/load", response_model=ScanOut)
def load_demo(body: DemoLoadIn | None = None) -> ScanOut:
    """Loads a built-in demo project (default: vulnerable-app) and starts a scan."""
    from config import ROOT_DIR

    name = body.name if body else "vulnerable-app"
    demo_dir = ROOT_DIR / "demo" / name
    if not demo_dir.exists() or not (demo_dir / "package.json").exists():
        raise HTTPException(status_code=404, detail=f"demo '{name}' not found")
    zip_path = Path(UPLOADS_DIR) / f"demo-{name}.zip"
    from security import make_zip

    make_zip(demo_dir, zip_path, exclude=("node_modules", ".git"))
    data = zip_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    db = SessionLocal()
    try:
        existing = db.query(Project).filter_by(sha256=sha256).first()
        if existing:
            project = existing
        else:
            project = Project(name=_demo_title(name), filename=f"demo-{name}.zip", sha256=sha256, size_bytes=len(data), status="UPLOADED")
            db.add(project)
            db.commit()
            db.refresh(project)
            (Path(UPLOADS_DIR) / f"{project.id}.zip").write_bytes(data)
        from schemas import ScanOptions

        opts = ScanOptions().model_dump()
        scan = Scan(project_id=project.id, state="UPLOADED", status="UPLOADED", intensity="standard", options=json.dumps(opts))
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    from orchestrator.scan_orchestrator import run_scan
    from orchestrator.task_queue import register_cancel, submit_scan

    cancel = threading.Event()
    CANCEL_EVENTS[scan_id] = cancel
    register_cancel(scan_id, cancel)
    submit_scan(scan_id, run_scan)

    db = SessionLocal()
    try:
        return ScanOut.model_validate(db.get(Scan, scan_id))
    finally:
        db.close()


def _demo_title(name: str) -> str:
    titles = {
        "vulnerable-app": "Vulnerable Demo App (mixed)",
        "injection-app": "Injection Demo App",
        "auth-app": "Auth & Authorization Demo App",
    }
    return titles.get(name, name.replace("-", " ").title() + " Demo")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _get_scan_row(scan_id: int) -> Scan:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")
        return scan
    finally:
        db.close()


def _effective_groq_key() -> str:
    if settings.groq_api_key:
        return settings.groq_api_key
    db = SessionLocal()
    try:
        row = db.get(Setting, "groq_api_key_enc")
        if row and row.value:
            return decrypt_value(row.value)
    finally:
        db.close()
    return ""


def _scan_cancel_event(scan_id: int) -> threading.Event | None:
    from orchestrator.task_queue import get_cancel_event

    return get_cancel_event(scan_id)


def _sandbox_mode() -> str:
    from services.sandbox import sandbox_mode

    return sandbox_mode()


def _build_graph_from_findings(scan_id: int) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = [{"id": "app", "label": "Application", "kind": "root"}]
    edges: list[dict[str, Any]] = []
    db = SessionLocal()
    try:
        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        for i, f in enumerate(findings):
            comp = f.affected_component or f.affected_file or "component"
            cid = f"comp-{i}"
            tid = f"test-{i}"
            fid = f"f-{f.id}"
            nodes.append({"id": cid, "label": comp[:60], "kind": "component"})
            nodes.append({"id": tid, "label": f.source, "kind": "test"})
            nodes.append({"id": fid, "label": f.title[:80], "kind": "finding", "severity": f.severity, "status": f.status})
            edges.append({"source": "app", "target": cid, "label": "route/component", "kind": "discovery"})
            edges.append({"source": cid, "target": tid, "label": "test", "kind": "test"})
            edges.append({"source": tid, "target": fid, "label": f.severity, "kind": "finding"})
            if f.patch_status in ("verified", "applied"):
                pid = f"patch-{i}"
                nodes.append({"id": pid, "label": "patch", "kind": "patch", "status": f.patch_status})
                edges.append({"source": fid, "target": pid, "label": "fix", "kind": "patch"})
    finally:
        db.close()
    return nodes + edges


def EvidenceOut_row(e: Evidence) -> dict[str, Any]:
    return {"id": e.id, "tool": e.tool, "target": e.target, "request": e.request, "response": e.response, "logs": e.logs, "screenshot": e.screenshot, "source_file": e.source_file, "source_line": e.source_line, "stack_trace": e.stack_trace, "reproduction_steps": e.reproduction_steps, "patch_diff": e.patch_diff, "verification_result": e.verification_result}


def PatchOut_row(p: Patch) -> dict[str, Any]:
    files = json.loads(p.files) if isinstance(p.files, str) else (p.files or {})
    return {"id": p.id, "scan_id": p.scan_id, "finding_id": p.finding_id, "status": p.status, "diff": p.diff, "files": files, "explanation": p.explanation, "created_at": p.created_at.isoformat() if p.created_at else None}


def VerificationOut_row(v: VerificationRun) -> dict[str, Any]:
    details = json.loads(v.details) if isinstance(v.details, str) else (v.details or {})
    return {"id": v.id, "scan_id": v.scan_id, "patch_id": v.patch_id, "finding_id": v.finding_id, "status": v.status, "build_pass": v.build_pass, "regression_pass": v.regression_pass, "exploit_blocked": v.exploit_blocked, "details": details, "created_at": v.created_at.isoformat() if v.created_at else None}
