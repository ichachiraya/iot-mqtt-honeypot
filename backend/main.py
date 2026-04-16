"""
backend/main.py

FastAPI application — HTTP transport only.
All analysis logic lives in backend/services.py.
The MQTT broker is started as a background task in on_startup().
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .database import get_stats, init_db, list_recent_alerts, list_recent_events
from .schemas import (
    AlertMessage,
    EventRecord,
    IngestResponse,
    RawEventIn,
    StatsResponse,
)
from .services import process_raw_event

app = FastAPI(title="MQTT Honeypot Backend", version="1.0.0")

# Serve dashboard static files
_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
app.mount("/dashboard", StaticFiles(directory=_DASHBOARD_DIR, html=True), name="dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup() -> None:
    init_db()

    # Reload ML model via the shared singleton in services.
    from .services import model_service
    model_service.reload()

    # Start fake MQTT broker on port 1883 as a background task.
    try:
        from broker.fake_broker import start_mqtt_broker
        asyncio.create_task(start_mqtt_broker())
    except Exception as exc:
        print(f"[MQTT Broker] Failed to start: {exc}")


@app.get("/")
def root() -> dict:
    return {"message": "MQTT Honeypot backend is running."}


# ── Ingest ────────────────────────────────────────────────────────────────────

@app.post("/ingest", response_model=IngestResponse)
def ingest_event(payload: RawEventIn) -> IngestResponse:
    return process_raw_event(payload)


# ── Query endpoints ───────────────────────────────────────────────────────────

@app.get("/events", response_model=list[EventRecord])
def get_events(limit: int = 50) -> list[EventRecord]:
    rows = list_recent_events(limit=limit)
    return [
        EventRecord(
            raw_event_id=row["raw_event_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            src_ip=row["src_ip"],
            client_id=row["client_id"],
            action=row["action"],
            topic=row["topic"],
            payload_size=row["payload_size"],
            connect_rate=row["connect_rate"],
            message_rate=row["message_rate"],
            topic_count=row["topic_count"],
            avg_payload_size=row["avg_payload_size"],
            failed_auth_count=row["failed_auth_count"],
            is_attack=bool(row["is_attack"]),
            predicted_attack_type=row["predicted_attack_type"],
            confidence=row["confidence"],
            severity=row["severity"],
            reason=row["reason"],
            rule_label=row["rule_label"],
            ml_label=row["ml_label"],
        )
        for row in rows
    ]


@app.get("/alerts", response_model=list[AlertMessage])
def get_alerts(limit: int = 20) -> list[AlertMessage]:
    rows = list_recent_alerts(limit=limit)
    return [
        AlertMessage(
            raw_event_id=row["raw_event_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            src_ip=row["src_ip"],
            predicted_attack_type=row["predicted_attack_type"],
            severity=row["severity"],
            confidence=row["confidence"],
            reason=row["reason"],
        )
        for row in rows
    ]


@app.get("/stats", response_model=StatsResponse)
def stats() -> StatsResponse:
    return StatsResponse(**get_stats())
