"""Tests for the zip-slip / decompression-bomb protections."""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security import secure_extract_zip, validate_zip, ZipUnsafeError, ZipValidationError  # noqa: E402


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


def test_plain_extract(tmp_path: Path) -> None:
    data = _zip_bytes([("hello.txt", b"hi"), ("sub/deep.txt", b"deep")])
    files = secure_extract_zip(data, tmp_path)
    assert (tmp_path / "hello.txt").read_bytes() == b"hi"
    assert (tmp_path / "sub" / "deep.txt").read_bytes() == b"deep"
    assert len(files) == 2


def test_zip_slip_traversal_rejected(tmp_path: Path) -> None:
    data = _zip_bytes([("../../evil.txt", b"pwned")])
    with pytest.raises(ZipUnsafeError):
        secure_extract_zip(data, tmp_path)


def test_absolute_path_rejected(tmp_path: Path) -> None:
    data = _zip_bytes([("/etc/evil.txt", b"pwned")])
    with pytest.raises(ZipUnsafeError):
        secure_extract_zip(data, tmp_path)


def test_invalid_zip_rejected(tmp_path: Path) -> None:
    with pytest.raises(ZipValidationError):
        validate_zip(b"this is definitely not a zip file at all")
    with pytest.raises(ZipValidationError):
        validate_zip(b"")


def test_no_path_escape_on_extract(tmp_path: Path) -> None:
    data = _zip_bytes([("a/b/c.txt", b"x")])
    secure_extract_zip(data, tmp_path)
    assert not any(p.name == "c.txt" and "a" not in p.parts for p in tmp_path.rglob("c.txt"))


def test_compression_bomb_ratio_guard(tmp_path: Path) -> None:
    import struct

    # Build a valid tiny zip, then patch the central directory's
    # uncompressed-size field to claim ~700 MiB (classic bomb header).
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\x00" * 4096)
    raw = bytearray(buf.getvalue())
    # central directory header: signature PK\x01\x02, uncompressed size at +24
    idx = raw.find(b"PK\x01\x02")
    assert idx >= 0
    struct.pack_into("<I", raw, idx + 24, 700 * 1024 * 1024)
    with pytest.raises(ZipUnsafeError):
        secure_extract_zip(bytes(raw), tmp_path)
