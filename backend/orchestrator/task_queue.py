"""Minimal in-process task queue for scan execution.

One background thread per scan; a global semaphore caps concurrent scans.
"""
from __future__ import annotations

import threading
from typing import Callable

MAX_CONCURRENT_SCANS = 4

_semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)
_active: set[int] = set()
_lock = threading.Lock()
_cancel_events: dict[int, threading.Event] = {}
_cancel_lock = threading.Lock()


def submit_scan(scan_id: int, fn: Callable[[int], None]) -> None:
    def _run() -> None:
        with _semaphore:
            with _lock:
                _active.add(scan_id)
            try:
                fn(scan_id)
            finally:
                with _lock:
                    _active.discard(scan_id)
                with _cancel_lock:
                    _cancel_events.pop(scan_id, None)

    threading.Thread(target=_run, name=f"scan-{scan_id}", daemon=True).start()


def active_scans() -> list[int]:
    with _lock:
        return sorted(_active)


def register_cancel(scan_id: int, event: threading.Event) -> None:
    with _cancel_lock:
        _cancel_events[scan_id] = event


def get_cancel_event(scan_id: int) -> threading.Event | None:
    with _cancel_lock:
        return _cancel_events.get(scan_id)
