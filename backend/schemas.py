from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


ActionType = Literal["connect", "publish", "auth_fail"]
AttackType = Literal["normal", "flood", "brute_force", "topic_scan", "oversized_payload"]
SeverityType = Literal["low", "medium", "high"]


class RawEventIn(BaseModel):
    timestamp: Optional[datetime] = None
    src_ip: str = Field(..., examples=["192.168.1.10"])
    client_id: str = Field(default="unknown_client")
    action: ActionType = Field(default="publish")
    topic: str = Field(default="/")
    payload: str = Field(default="")
    payload_size: Optional[int] = None
    qos: int = Field(default=0, ge=0, le=2)
    username_used: Optional[str] = None


class RawEventStored(BaseModel):
    timestamp: datetime
    src_ip: str
    client_id: str
    action: ActionType
    topic: str
    payload: str
    payload_size: int
    qos: int
    username_used: Optional[str] = None


class FeatureEvent(BaseModel):
    timestamp: datetime
    src_ip: str
    connect_rate: float
    message_rate: float
    topic_count: int
    avg_payload_size: float
    failed_auth_count: int


class RuleDecision(BaseModel):
    is_attack: bool
    predicted_attack_type: AttackType
    severity: SeverityType
    reason: str


class MlDecision(BaseModel):
    predicted_attack_type: AttackType
    confidence: float


class PredictionResult(BaseModel):
    is_attack: bool
    predicted_attack_type: AttackType
    confidence: float
    severity: SeverityType
    reason: str
    rule_label: AttackType
    ml_label: Optional[AttackType] = None


class IngestResponse(BaseModel):
    raw_event_id: int
    prediction: PredictionResult
    features: FeatureEvent


class EventRecord(BaseModel):
    raw_event_id: int
    timestamp: datetime
    src_ip: str
    client_id: str
    action: ActionType
    topic: str
    payload_size: int
    connect_rate: float
    message_rate: float
    topic_count: int
    avg_payload_size: float
    failed_auth_count: int
    is_attack: bool
    predicted_attack_type: AttackType
    confidence: float
    severity: SeverityType
    reason: str
    rule_label: AttackType
    ml_label: Optional[AttackType] = None


class AlertMessage(BaseModel):
    raw_event_id: int
    timestamp: datetime
    src_ip: str
    predicted_attack_type: AttackType
    severity: SeverityType
    confidence: float
    reason: str


class StatsResponse(BaseModel):
    total_events: int
    total_alerts: int
    recent_attack_ratio: float
    attack_type_counts: dict[str, int]
