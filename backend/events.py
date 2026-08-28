"""In-memory event bus for live scan streaming + persistent step snapshots.

The orchestrator publishes events; the SSE endpoint streams them to the
frontend. Completed events also live in the DB (scan_steps) so dashboards
survive a page refresh.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from typing import Any

EVENT_QUEUE_SIZE = 2000


class EventBus:
    def __init__(self) -> None:
        self._queues: dict[int, deque[dict[str, Any]]] = defaultdict(deque)
        self._locks: dict[int, threading.Lock] = defaultdict(threading.Lock)
        self._cond: dict[int, threading.Condition] = {}

    def _cond_for(self, scan_id: int) -> threading.Condition:
        with self._locks[scan_id]:
            if scan_id not in self._cond:
                self._cond[scan_id] = threading.Condition()
            return self._cond[scan_id]

    def publish(self, scan_id: int, event: dict[str, Any]) -> None:
        event = dict(event)
        event.setdefault("ts", time.time())
        cond = self._cond_for(scan_id)
        with cond:
            self._queues[scan_id].append(event)
            if len(self._queues[scan_id]) > EVENT_QUEUE_SIZE:
                self._queues[scan_id].popleft()
            cond.notify_all()

    def subscribe(self, scan_id: int):
        """Generator yielding events for an SSE stream (blocks)."""
        cond = self._cond_for(scan_id)
        q = self._queues[scan_id]
        last_index = len(q)
        while True:
            with cond:
                cond.wait(timeout=15)
                while last_index < len(q):
                    event = q[last_index]
                    last_index += 1
                    yield "data: " + json.dumps(event, default=str) + "\n\n"
                # heartbeat so proxies keep the stream open
                yield ": keep-alive\n\n"

    def close(self, scan_id: int) -> None:
        cond = self._cond_for(scan_id)
        with cond:
            self._queues.pop(scan_id, None)
            cond.notify_all()


bus = EventBus()


def ev(scan_id: int, kind: str, **payload: Any) -> None:
    """Shortcut: publish a typed event with sensible defaults."""
    event = {"type": kind, **payload}
    if "msg" in payload:
        event["message"] = payload["msg"]
    bus.publish(scan_id, event)


def log(scan_id: int, message: str, level: str = "info") -> None:
    ev(scan_id, "log", msg=message, level=level)


def agent_event(scan_id: int, agent: str, status: str, detail: str = "") -> None:
    ev(scan_id, "agent", agent=agent, status=status, msg=detail or status)


def progress_event(scan_id: int, progress: float, state: str, detail: str = "") -> None:
    ev(scan_id, "progress", progress=round(progress, 2), state=state, msg=detail)


def finding_event(scan_id: int, finding: dict[str, Any]) -> None:
    ev(scan_id, "finding", finding=finding)


def tool_event(scan_id: int, tool: str, status: str, msg: str = "") -> None:
    ev(scan_id, "tool", tool=tool, status=status, msg=msg)
