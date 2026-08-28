"""SentinelForge AI - backend entrypoint.

Run:  uvicorn main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import ROOT_DIR, settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("sentinelforge")


def _add_tool_dirs_to_path() -> None:
    """Put the bundled toolchain (tools/bin) and the active venv's scripts dir
    on PATH so tool detection (shutil.which) and subprocess execution find the
    installed security tools regardless of how the server was launched."""
    candidates = [ROOT_DIR / "tools" / "bin", Path(sys.executable).parent]
    existing = os.environ.get("PATH", "")
    parts = [str(c) for c in candidates if c.exists() and str(c) not in existing]
    if parts:
        os.environ["PATH"] = os.pathsep.join(parts) + os.pathsep + existing
        logger.info("Tool dirs added to PATH: %s", ", ".join(parts))


_add_tool_dirs_to_path()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from database import init_db
    from database import SessionLocal
    from models import Setting
    from security import decrypt_value

    init_db()
    # Load persisted (encrypted) Groq settings if env var is empty.
    if not settings.groq_api_key:
        db = SessionLocal()
        try:
            row = db.get(Setting, "groq_api_key_enc")
            if row and row.value:
                settings.groq_api_key = decrypt_value(row.value)
            row = db.get(Setting, "groq_model")
            if row and row.value:
                settings.groq_model = row.value
        finally:
            db.close()
    logger.info("SentinelForge AI backend ready - sandbox mode: %s", _sandbox_mode())
    yield


def _sandbox_mode() -> str:
    from services.sandbox import sandbox_mode

    return sandbox_mode()


app = FastAPI(title="SentinelForge AI", version="1.0.0", lifespan=lifespan)

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from api.routes import router  # noqa: E402

app.include_router(router)

# Serve the built frontend when present (production/docker mode).
_dist = ROOT_DIR / "frontend" / "dist"
if _dist.exists():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="frontend")
    logger.info("Serving frontend build from %s", _dist)


@app.get("/")
def root() -> dict:
    return {"name": "SentinelForge AI", "docs": "/docs", "health": "/api/health"}
