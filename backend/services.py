"""
backend/services.py

Central processing pipeline — shared by both the HTTP /ingest endpoint
and the fake MQTT broker. Any new transport (MQTT, WebSocket, etc.)
just calls process_raw_event() and gets the same analysis.
"""
from __future__ import annotations

from datetime import datetime

from .database import (
    get_auth_fail_count_by_ip,
    get_recent_source_window,
    insert_prediction,
    insert_raw_event,
)
from .ml_model import ModelService
from .rules import classify_with_rules
from .schemas import (
    FeatureEvent,
    IngestResponse,
    PredictionResult,
    RawEventIn,
    RawEventStored,
)

# Shared ML model singleton — loaded once, used by both HTTP and MQTT paths.
model_service = ModelService()

SUSPICIOUS_USERNAMES = {"admin", "root", "test", "mqtt", "guest"}


# ── Step 1: Normalise ──────────────────────────────────────────────────────────

def normalize_raw_event(payload: RawEventIn) -> RawEventStored:
    payload_size = (
        payload.payload_size
        if payload.payload_size is not None
        else len(payload.payload)
    )
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


# ── Step 2: Feature extraction ────────────────────────────────────────────────

def extract_features(raw_event: RawEventStored) -> FeatureEvent:
    history = get_recent_source_window(raw_event.src_ip, raw_event.client_id, seconds=60)

    connect_events   = sum(1 for row in history if row["action"] == "connect")
    publish_events   = sum(1 for row in history if row["action"] == "publish")
    topics           = {row["topic"] for row in history if row["topic"]}
    payload_sizes    = [int(row["payload_size"]) for row in history]

    # Include current event.
    if raw_event.action == "connect":
        connect_events += 1
    if raw_event.action == "publish":
        publish_events += 1
    if raw_event.topic:
        topics.add(raw_event.topic)
    payload_sizes.append(raw_event.payload_size)

    # Topic depth heuristic.
    if raw_event.topic.count("/") >= 4:
        topics.add(f"{raw_event.topic}#deep")

    # Auth fails: count across ALL client_ids from this IP (catches rotating client_id brute force)
    # +1 for the current event if it's an auth_fail
    auth_fail_count = get_auth_fail_count_by_ip(raw_event.src_ip, seconds=60)
    if raw_event.action == "auth_fail":
        auth_fail_count += 1

    return FeatureEvent(
        timestamp=raw_event.timestamp,
        src_ip=raw_event.src_ip,
        connect_rate=float(connect_events),
        message_rate=float(publish_events),
        topic_count=len(topics),
        avg_payload_size=round(sum(payload_sizes) / len(payload_sizes), 2),
        failed_auth_count=auth_fail_count,
    )


# ── Step 3: Combine rule + ML decisions ───────────────────────────────────────

def combine_decisions(rule_result, ml_result) -> PredictionResult:
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

    if rule_result.is_attack:
        return PredictionResult(
            is_attack=True,
            predicted_attack_type=rule_result.predicted_attack_type,
            confidence=round(max(float(ml_result.confidence), 0.85), 2),
            severity=rule_result.severity,
            reason=f"{rule_result.reason} ML also predicted {ml_result.predicted_attack_type}.",
            rule_label=rule_result.predicted_attack_type,
            ml_label=ml_result.predicted_attack_type,
        )

    is_attack = ml_result.predicted_attack_type != "normal"
    return PredictionResult(
        is_attack=is_attack,
        predicted_attack_type=ml_result.predicted_attack_type,
        confidence=float(ml_result.confidence),
        severity="medium" if is_attack else "low",
        reason=(
            f"ML predicted {ml_result.predicted_attack_type} even though rules stayed normal."
            if is_attack
            else rule_result.reason
        ),
        rule_label=rule_result.predicted_attack_type,
        ml_label=ml_result.predicted_attack_type,
    )


# ── Central pipeline ──────────────────────────────────────────────────────────

def process_raw_event(payload: RawEventIn) -> IngestResponse:
    """
    Full analysis pipeline. Called by:
      - HTTP POST /ingest  (main.py)
      - MQTT broker        (broker/fake_broker.py)
    """
    raw_event   = normalize_raw_event(payload)
    features    = extract_features(raw_event)
    rule_result = classify_with_rules(features)
    ml_result   = model_service.predict(features)
    prediction  = combine_decisions(rule_result, ml_result)

    raw_event_id = insert_raw_event(raw_event, features)
    insert_prediction(raw_event_id, prediction)

    return IngestResponse(
        raw_event_id=raw_event_id,
        prediction=prediction,
        features=features,
    )
