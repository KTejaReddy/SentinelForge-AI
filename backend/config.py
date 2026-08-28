"""SentinelForge AI - central configuration.

All values can be overridden through environment variables or a .env file
at the repository root. Secrets are never hardcoded and never exposed to
the frontend.
"""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent   # backend/
ROOT_DIR = BACKEND_DIR.parent                    # repository root

DATA_DIR = ROOT_DIR / "data"
WORKSPACES_DIR = ROOT_DIR / "workspaces"
SCANS_DIR = ROOT_DIR / "scans"
REPORTS_DIR = ROOT_DIR / "reports"
UPLOADS_DIR = ROOT_DIR / "uploads"

for _d in (DATA_DIR, WORKSPACES_DIR, SCANS_DIR, REPORTS_DIR, UPLOADS_DIR):
    _d.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(ROOT_DIR / ".env"), extra="ignore")

    # --- AI / Groq ---
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-20b"  # lighter model, fewer rate limits
    groq_max_tokens: int = 4096
    groq_temperature: float = 0.2
    groq_base_url: str = "https://api.groq.com/openai/v1"

    # --- Database ---
    database_url: str = f"sqlite:///{DATA_DIR / 'sentinelforge.db'}"

    # --- Scan limits ---
    max_upload_size_mb: int = 200
    scan_timeout_seconds: int = 1200  # 20 minutes for full pipeline
    max_repair_iterations: int = 1  # one attempt per finding for speed
    max_ai_calls_per_scan: int = 80
    default_intensity: str = "standard"  # standard | aggressive | maximum_safe

    # --- Sandbox ---
    docker_enabled: bool = True  # auto-detected; set false to force local mode
    sandbox_memory_mb: int = 2048
    sandbox_cpu_limit: float = 2.0
    sandbox_max_processes: int = 256
    sandbox_image: str = "sentinelforge/sandbox:latest"

    # --- Server ---
    backend_port: int = 8000
    frontend_port: int = 5173
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- Scoring weights (documented in README) ---
    score_w_security: float = 0.45
    score_w_reliability: float = 0.30
    score_w_code_health: float = 0.25

    # --- Internal ---
    max_finding_context_bytes: int = 24_000
    max_context_files: int = 40
    max_single_file_bytes: int = 60_000
    groq_timeout_seconds: int = 30
    ai_call_budget_per_scan: int = 80
    ai_phase_timeout_seconds: int = 180  # max time for the entire AI analysis phase


def get_settings() -> Settings:
    return Settings()


settings = get_settings()
