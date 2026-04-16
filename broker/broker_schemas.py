"""
broker/broker_schemas.py

Simple dataclasses representing parsed MQTT packets.
These are internal broker types — not Pydantic models.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MqttConnect:
    """Parsed MQTT CONNECT packet."""
    client_id: str
    username: str | None = None
    password: str | None = None
    protocol_version: int = 4     # 4 = MQTT 3.1.1


@dataclass
class MqttPublish:
    """Parsed MQTT PUBLISH packet."""
    topic: str
    payload: str
    qos: int = 0


@dataclass
class MqttSubscribe:
    """Parsed MQTT SUBSCRIBE packet."""
    topics: list[str] = field(default_factory=list)
    packet_id: int = 0


@dataclass
class MqttUnknown:
    """Packet type we received but don't handle."""
    packet_type: int
    raw: bytes
