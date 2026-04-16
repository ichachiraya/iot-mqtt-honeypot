from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .database import (
    get_recent_source_window,
    get_stats,
    init_db,
    insert_prediction,
    insert_raw_event,
    list_recent_alerts,
    list_recent_events,
)
from .ml_model import ModelService
from .rules import classify_with_rules
from .schemas import (
    AlertMessage,
    EventRecord,
    FeatureEvent,
    IngestResponse,
    PredictionResult,
    RawEventIn,
    RawEventStored,
    StatsResponse,
)

app = FastAPI(title="MQTT Honeypot Backend", version="1.0.0")
model_service = ModelService()

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
def on_startup() -> None:
    init_db()
    model_service.reload()


@app.get("/")
def root() -> dict:
    return {"message": "MQTT Honeypot backend is running."}


def normalize_raw_event(payload: RawEventIn) -> RawEventStored:
    payload_size = payload.payload_size if payload.payload_size is not None else len(payload.payload)
    timestamp = payload.timestamp or datetime.now()

    return RawEventStored(
        timestamp=timestamp,
        src_ip=payload.src_ip,
        client_id=payload.client_id,
        action=payload.action,
        topic=payload.topic,
        payload=payload.payload,
        payload_size=payload_size,
        qos=payload.qos,
        username_used=payload.username_used,
    )


SUSPICIOUS_USERNAMES = {"admin", "root", "test", "mqtt", "guest"}


def extract_features(raw_event: RawEventStored) -> FeatureEvent:
    history = get_recent_source_window(raw_event.src_ip, seconds=60)

    connect_events = sum(1 for row in history if row["action"] == "connect")
    publish_events = sum(1 for row in history if row["action"] == "publish")
    auth_fail_events = sum(1 for row in history if row["action"] == "auth_fail")
    topics = {row["topic"] for row in history if row["topic"]}
    payload_sizes = [int(row["payload_size"]) for row in history]

    # Include current event before saving it.
    if raw_event.action == "connect":
        connect_events += 1
    if raw_event.action == "publish":
        publish_events += 1
    if raw_event.action == "auth_fail":
        auth_fail_events += 1
    if raw_event.topic:
        topics.add(raw_event.topic)
    payload_sizes.append(raw_event.payload_size)

    # Lightweight heuristics to make a single event still informative.
    if raw_event.username_used and raw_event.username_used.lower() in SUSPICIOUS_USERNAMES:
        auth_fail_events += 1
    if raw_event.topic.count("/") >= 4:
        topics.add(f"{raw_event.topic}#deep")

    return FeatureEvent(
        timestamp=raw_event.timestamp,
        src_ip=raw_event.src_ip,
        connect_rate=float(connect_events),
        message_rate=float(publish_events),
        topic_count=len(topics),
        avg_payload_size=round(sum(payload_sizes) / len(payload_sizes), 2),
        failed_auth_count=auth_fail_events,
    )


def combine_decisions(rule_result, ml_result: Optional[object]) -> PredictionResult:
    if ml_result is None:
        confidence = 0.9 if rule_result.is_attack else 0.7
        return PredictionResult(
            is_attack=rule_result.is_attack,
            predicted_attack_type=rule_result.predicted_attack_type,
            confidence=confidence,
            severity=rule_result.severity,
            reason=rule_result.reason,
            rule_label=rule_result.predicted_attack_type,
            ml_label=None,
        )

    # Rule-based first for clear attacks, ML as support/confidence.
    if rule_result.is_attack:
        final_type = rule_result.predicted_attack_type
        confidence = max(float(ml_result.confidence), 0.85)
        severity = rule_result.severity
        reason = f"{rule_result.reason} ML also predicted {ml_result.predicted_attack_type}."
        return PredictionResult(
            is_attack=True,
            predicted_attack_type=final_type,
            confidence=round(confidence, 2),
            severity=severity,
            reason=reason,
            rule_label=rule_result.predicted_attack_type,
            ml_label=ml_result.predicted_attack_type,
        )

    is_attack = ml_result.predicted_attack_type != "normal"
    severity = "medium" if is_attack else "low"
    reason = (
        f"ML predicted {ml_result.predicted_attack_type} even though rules stayed normal."
        if is_attack
        else rule_result.reason
    )
    return PredictionResult(
        is_attack=is_attack,
        predicted_attack_type=ml_result.predicted_attack_type,
        confidence=float(ml_result.confidence),
        severity=severity,
        reason=reason,
        rule_label=rule_result.predicted_attack_type,
        ml_label=ml_result.predicted_attack_type,
    )


@app.post("/ingest", response_model=IngestResponse)
def ingest_event(payload: RawEventIn) -> IngestResponse:
    raw_event = normalize_raw_event(payload)
    features = extract_features(raw_event)
    rule_result = classify_with_rules(features)
    ml_result = model_service.predict(features)
    prediction = combine_decisions(rule_result, ml_result)

    raw_event_id = insert_raw_event(raw_event, features)
    insert_prediction(raw_event_id, prediction)

    return IngestResponse(raw_event_id=raw_event_id, prediction=prediction, features=features)


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
