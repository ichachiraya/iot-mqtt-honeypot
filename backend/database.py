from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from backend.schemas import FeatureEvent, PredictionResult, RawEventStored

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                client_id TEXT NOT NULL,
                action TEXT NOT NULL,
                topic TEXT NOT NULL,
                payload TEXT NOT NULL,
                payload_size INTEGER NOT NULL,
                qos INTEGER NOT NULL,
                username_used TEXT,
                connect_rate REAL NOT NULL,
                message_rate REAL NOT NULL,
                topic_count INTEGER NOT NULL,
                avg_payload_size REAL NOT NULL,
                failed_auth_count INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_event_id INTEGER NOT NULL,
                is_attack INTEGER NOT NULL,
                predicted_attack_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                rule_label TEXT NOT NULL,
                ml_label TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(raw_event_id) REFERENCES raw_events(id)
            )
            """
        )


def insert_raw_event(raw_event: RawEventStored, features: FeatureEvent) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO raw_events (
                timestamp, src_ip, client_id, action, topic, payload, payload_size,
                qos, username_used, connect_rate, message_rate, topic_count,
                avg_payload_size, failed_auth_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                raw_event.timestamp.isoformat(),
                raw_event.src_ip,
                raw_event.client_id,
                raw_event.action,
                raw_event.topic,
                raw_event.payload,
                raw_event.payload_size,
                raw_event.qos,
                raw_event.username_used,
                features.connect_rate,
                features.message_rate,
                features.topic_count,
                features.avg_payload_size,
                features.failed_auth_count,
            ),
        )
        return int(cursor.lastrowid)


def insert_prediction(raw_event_id: int, prediction: PredictionResult) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO predictions (
                raw_event_id, is_attack, predicted_attack_type, confidence,
                severity, reason, rule_label, ml_label
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                raw_event_id,
                int(prediction.is_attack),
                prediction.predicted_attack_type,
                prediction.confidence,
                prediction.severity,
                prediction.reason,
                prediction.rule_label,
                prediction.ml_label,
            ),
        )


def get_recent_source_window(src_ip: str, seconds: int = 60) -> list[sqlite3.Row]:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT *
            FROM raw_events
            WHERE src_ip = ?
              AND datetime(timestamp) >= datetime('now', ?)
            ORDER BY timestamp DESC
            """,
            (src_ip, f"-{seconds} seconds"),
        )
        return cursor.fetchall()


def list_recent_events(limit: int = 50) -> list[sqlite3.Row]:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT
                r.id AS raw_event_id,
                r.timestamp,
                r.src_ip,
                r.client_id,
                r.action,
                r.topic,
                r.payload_size,
                r.connect_rate,
                r.message_rate,
                r.topic_count,
                r.avg_payload_size,
                r.failed_auth_count,
                p.is_attack,
                p.predicted_attack_type,
                p.confidence,
                p.severity,
                p.reason,
                p.rule_label,
                p.ml_label
            FROM raw_events r
            LEFT JOIN predictions p ON p.raw_event_id = r.id
            ORDER BY r.timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cursor.fetchall()


def list_recent_alerts(limit: int = 20) -> list[sqlite3.Row]:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT
                r.id AS raw_event_id,
                r.timestamp,
                r.src_ip,
                p.predicted_attack_type,
                p.severity,
                p.confidence,
                p.reason
            FROM raw_events r
            JOIN predictions p ON p.raw_event_id = r.id
            WHERE p.is_attack = 1
            ORDER BY r.timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cursor.fetchall()


def get_stats() -> dict:
    with get_connection() as conn:
        total_events = conn.execute("SELECT COUNT(*) AS count FROM raw_events").fetchone()["count"]
        total_alerts = conn.execute(
            "SELECT COUNT(*) AS count FROM predictions WHERE is_attack = 1"
        ).fetchone()["count"]
        attack_rows = conn.execute(
            """
            SELECT predicted_attack_type, COUNT(*) AS count
            FROM predictions
            WHERE is_attack = 1
            GROUP BY predicted_attack_type
            ORDER BY count DESC
            """
        ).fetchall()
        recent_rows = conn.execute(
            "SELECT is_attack FROM predictions ORDER BY id DESC LIMIT 100"
        ).fetchall()

    attack_type_counts = {row["predicted_attack_type"]: row["count"] for row in attack_rows}
    recent_count = len(recent_rows)
    recent_alert_count = sum(int(row["is_attack"]) for row in recent_rows)
    recent_attack_ratio = (recent_alert_count / recent_count) if recent_count else 0.0

    return {
        "total_events": int(total_events),
        "total_alerts": int(total_alerts),
        "recent_attack_ratio": round(recent_attack_ratio, 2),
        "attack_type_counts": attack_type_counts,
    }
