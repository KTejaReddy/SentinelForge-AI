"""SQLAlchemy setup - SQLite by default, survives dashboard refreshes."""
from __future__ import annotations

import json

from sqlalchemy import String, Text, TypeDecorator, create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import settings


class JsonText(TypeDecorator):
    """Text column that transparently serializes dict/list values to JSON.

    Tolerant: strings assigned directly are stored as-is, and stored JSON is
    parsed back into dicts on read.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None or isinstance(value, (str, bytes)):
            return value
        try:
            return json.dumps(value, default=str)
        except TypeError:
            return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return {}
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):  # pragma: no cover
    if settings.database_url.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from models import (  # noqa: F401  (register models)
        AgentRun, Evidence, Finding, Patch, Project, Report, Scan, ScanStep,
        Setting, ToolRun, VerificationRun,
    )

    Base.metadata.create_all(bind=engine)
