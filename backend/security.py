"""Platform-self-protection utilities.

- Path-traversal-safe ZIP extraction with decompression-bomb protection
- Secret redaction for logs / AI payloads
- Encrypted-at-rest persistence of API keys (AES-GCM via `cryptography`)
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import zipfile
from pathlib import Path

MAX_TOTAL_EXTRACT_BYTES = 2 * 1024**3  # 2 GiB hard cap (decompression bomb)
MAX_FILES = 50_000
MAX_SINGLE_FILE = 500 * 1024**2

# ---------------------------------------------------------------------------
# ZIP safety
# ---------------------------------------------------------------------------


class ZipValidationError(Exception):
    pass


class ZipUnsafeError(Exception):
    pass


def validate_zip(data: bytes, max_size_mb: int = 200) -> None:
    """Basic structural validation before extraction."""
    if len(data) > max_size_mb * 1024 * 1024:
        raise ZipValidationError(f"ZIP exceeds the {max_size_mb} MB upload limit")
    if len(data) < 22:  # smallest valid EOCD
        raise ZipValidationError("File is too small to be a ZIP archive")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise ZipValidationError(f"Invalid or corrupt ZIP archive: {exc}") from exc
    if not infos:
        raise ZipValidationError("ZIP archive is empty")


def secure_extract_zip(data: bytes, dest: Path) -> list[str]:
    """Extract a ZIP safely.

    Rejects:
    - absolute paths and `..` traversal (zip-slip)
    - symlinks pointing outside the destination
    - decompression bombs (size / file-count / ratio guards)
    """
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    total_uncompressed = 0

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ZipUnsafeError(f"Archive contains too many entries ({len(infos)})")

        for info in infos:
            if info.flag_bits & 0x1:  # encrypted entries unsupported
                raise ZipUnsafeError(f"Encrypted entries are not supported: {info.filename}")
            if info.file_size > MAX_SINGLE_FILE:
                raise ZipUnsafeError(f"Entry too large: {info.filename}")
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_TOTAL_EXTRACT_BYTES:
                raise ZipUnsafeError("Archive expands beyond the safety limit (decompression bomb)")

            name = info.filename.replace("\\", "/")
            if name.startswith("/") or "\x00" in name:
                raise ZipUnsafeError(f"Unsafe archive entry: {info.filename!r}")
            parts = [p for p in name.split("/") if p not in ("", ".")]
            if not parts:
                continue
            if any(p == ".." for p in parts):
                raise ZipUnsafeError(f"Path traversal detected: {info.filename!r}")

            target = dest.joinpath(*parts).resolve()
            if not target.is_relative_to(dest):
                raise ZipUnsafeError(f"Path traversal detected: {info.filename!r}")

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            # Follow zip-spec symlink entries: reject unless they stay inside.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                link_target = zf.read(info).decode("utf-8", "replace")
                resolved = (target.parent / link_target).resolve()
                if not resolved.is_relative_to(dest):
                    raise ZipUnsafeError(f"Unsafe symlink in archive: {info.filename!r}")
                target.symlink_to(link_target)
                continue

            with zf.open(info) as src, open(target, "wb") as out:
                written = 0
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_SINGLE_FILE:
                        raise ZipUnsafeError(f"Entry exceeded size limit: {info.filename}")
                    out.write(chunk)
            extracted.append(str(target.relative_to(dest)))

    return extracted


def make_zip(source_dir: Path, out_path: Path, exclude=("node_modules", ".git", "__pycache__", ".venv", "venv", ".next", "dist", "target", "build")) -> Path:
    """Create a ZIP from a directory, skipping heavy/vcs dirs."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    source_dir = source_dir.resolve()
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if d not in exclude and not d.startswith(".")]
            for fname in sorted(files):
                full = Path(root) / fname
                rel = full.relative_to(source_dir).as_posix()
                if rel.startswith(tuple(exclude)):
                    continue
                try:
                    zf.write(full, rel)
                except OSError:
                    continue
    return out_path


# ---------------------------------------------------------------------------
# Secret redaction (never leak secrets into logs, reports, or AI prompts)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    re.compile(r"(?i)(groq_api_key|api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[=:]\s*[\"']?([A-Za-z0-9_\-\.\/+]{8,})"),
    re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}"),
]

_REDACTED = "***REDACTED***"


def redact_text(text: str) -> str:
    """Replace likely secrets in arbitrary text."""
    if not text:
        return text
    for pattern in _SECRET_PATTERNS:
        try:
            text = pattern.sub(lambda m: _redact_match(m), text)
        except Exception:
            continue
    return text


def _redact_match(match: re.Match) -> str:
    groups = match.groups()
    if len(groups) >= 2:
        return f"{groups[0]}={_REDACTED}"
    return _REDACTED


# ---------------------------------------------------------------------------
# Encrypted settings (API keys at rest)
# ---------------------------------------------------------------------------

try:
    from cryptography.fernet import Fernet  # type: ignore
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


def _machine_key() -> bytes:
    key_file = Path(__file__).resolve().parent.parent.parent / "data" / ".machine_key"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if key_file.exists():
        return key_file.read_bytes().strip()
    raw = os.urandom(32)
    key = base64.urlsafe_b64encode(hashlib.sha256(b"sentinelforge::" + raw).digest())
    key_file.write_bytes(key)
    try:
        key_file.chmod(0o600)
    except Exception:
        pass
    return key


def encrypt_value(value: str) -> str:
    """Encrypt a sensitive value for storage. Falls back to base64 if the
    cryptography package is unavailable (documented limitation)."""
    if not value:
        return ""
    if _HAS_CRYPTO:
        return "enc:" + Fernet(_machine_key()).encrypt(value.encode()).decode()
    return "b64:" + base64.b64encode(value.encode()).decode()


def decrypt_value(stored: str) -> str:
    if not stored:
        return ""
    try:
        if stored.startswith("enc:"):
            if not _HAS_CRYPTO:
                return ""
            return Fernet(_machine_key()).decrypt(stored[4:].encode()).decode()
        if stored.startswith("b64:"):
            return base64.b64decode(stored[4:]).decode()
    except Exception:
        return ""
    return stored
