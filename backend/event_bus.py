"""
backend/event_bus.py

In-memory broadcast bus for Server-Sent Events (SSE).
When process_raw_event() finishes, it calls broadcast() to push the
result to every connected dashboard client in real time.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

# All currently connected SSE client queues
_subscribers: list[asyncio.Queue[str]] = []


def subscribe() -> asyncio.Queue[str]:
    """Register a new SSE client. Returns its personal queue."""
    q: asyncio.Queue[str] = asyncio.Queue(maxsize=256)
    _subscribers.append(q)
    return q


def unsubscribe(q: asyncio.Queue[str]) -> None:
    """Remove client queue on disconnect."""
    try:
        _subscribers.remove(q)
    except ValueError:
        pass


def _json_serial(obj: Any) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def broadcast(event_type: str, data: dict) -> None:
    """
    Push an event to every connected SSE client.
    Non-blocking: if a client's queue is full we silently drop.
    """
    payload = json.dumps(data, default=_json_serial)
    message = f"event: {event_type}\ndata: {payload}\n\n"
    for q in list(_subscribers):
        try:
            q.put_nowait(message)
        except asyncio.QueueFull:
            pass  # slow client — drop this message
