"""
broker/mqtt_parser.py

Parses raw MQTT 3.1.1 bytes into structured packet objects.

Supports:
  - CONNECT   (0x10)  — extracts client_id, username, password
  - PUBLISH   (0x30)  — extracts topic, payload, qos
  - SUBSCRIBE (0x82)  — extracts topic list
  - PINGREQ   (0xC0)  — acknowledged, no data extracted
  - DISCONNECT(0xE0)  — signals client disconnect

Reference: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
"""
from __future__ import annotations

from broker.broker_schemas import (
    MqttConnect,
    MqttPublish,
    MqttSubscribe,
    MqttUnknown,
)

# ── MQTT packet type constants ────────────────────────────────────────────────
CONNECT    = 0x10
CONNACK    = 0x20
PUBLISH    = 0x30
PUBACK     = 0x40
SUBSCRIBE  = 0x82
SUBACK     = 0x90
PINGREQ    = 0xC0
PINGRESP   = 0xD0
DISCONNECT = 0xE0


def _read_utf8(data: bytes, offset: int) -> tuple[str, int]:
    """Read a length-prefixed UTF-8 string. Returns (string, new_offset)."""
    length = (data[offset] << 8) | data[offset + 1]
    text = data[offset + 2: offset + 2 + length].decode("utf-8", errors="replace")
    return text, offset + 2 + length


def _decode_remaining_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode MQTT variable-length remaining length field."""
    multiplier = 1
    value = 0
    while True:
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) * multiplier
        multiplier *= 128
        if not (byte & 0x80):
            break
    return value, offset


def parse(data: bytes) -> MqttConnect | MqttPublish | MqttSubscribe | MqttUnknown | None:
    """
    Parse the first MQTT packet from raw bytes.
    Returns None if data is too short or malformed.
    """
    if len(data) < 2:
        return None

    packet_type = data[0] & 0xF0   # upper nibble
    flags       = data[0] & 0x0F   # lower nibble

    try:
        remaining_length, header_end = _decode_remaining_length(data, 1)
        payload = data[header_end: header_end + remaining_length]

        # ── CONNECT ──────────────────────────────────────────────────────────
        if packet_type == CONNECT:
            return _parse_connect(payload)

        # ── PUBLISH ──────────────────────────────────────────────────────────
        if packet_type == PUBLISH:
            qos = (flags >> 1) & 0x03
            return _parse_publish(payload, qos)

        # ── SUBSCRIBE ────────────────────────────────────────────────────────
        if data[0] == SUBSCRIBE:
            return _parse_subscribe(payload)

        # ── PINGREQ / DISCONNECT — no payload ────────────────────────────────
        if data[0] in (PINGREQ, DISCONNECT):
            return MqttUnknown(packet_type=data[0], raw=data)

        return MqttUnknown(packet_type=data[0], raw=data)

    except (IndexError, UnicodeDecodeError):
        return None


def _parse_connect(payload: bytes) -> MqttConnect:
    """Parse CONNECT packet payload."""
    # Protocol name (e.g. "MQTT") — skip it
    proto_name, offset = _read_utf8(payload, 0)
    protocol_version = payload[offset]
    connect_flags    = payload[offset + 1]
    # keep_alive     = (payload[offset + 2] << 8) | payload[offset + 3]
    offset += 4

    # Payload starts with client_id
    client_id, offset = _read_utf8(payload, offset)

    username = None
    password = None

    # Bit 7 of connect_flags = username present
    if connect_flags & 0x80:
        username, offset = _read_utf8(payload, offset)

    # Bit 6 = password present
    if connect_flags & 0x40:
        password, offset = _read_utf8(payload, offset)

    return MqttConnect(
        client_id=client_id or "unknown",
        username=username,
        password=password,
        protocol_version=protocol_version,
    )


def _parse_publish(payload: bytes, qos: int) -> MqttPublish:
    """Parse PUBLISH packet payload."""
    topic, offset = _read_utf8(payload, 0)

    # If QoS > 0 there's a 2-byte packet identifier we skip
    if qos > 0:
        offset += 2

    message = payload[offset:].decode("utf-8", errors="replace")

    return MqttPublish(topic=topic, payload=message, qos=qos)


def _parse_subscribe(payload: bytes) -> MqttSubscribe:
    """Parse SUBSCRIBE packet payload."""
    packet_id = (payload[0] << 8) | payload[1]
    offset    = 2
    topics: list[str] = []

    while offset < len(payload):
        topic, offset = _read_utf8(payload, offset)
        _qos = payload[offset]   # requested QoS — we log but don't enforce
        offset += 1
        topics.append(topic)

    return MqttSubscribe(topics=topics, packet_id=packet_id)


# ── ACK response builders ─────────────────────────────────────────────────────

def build_connack(return_code: int = 0) -> bytes:
    """CONNACK: 0x20 0x02 <session_present=0> <return_code>."""
    return bytes([CONNACK, 0x02, 0x00, return_code])


def build_puback(packet_id: int) -> bytes:
    """PUBACK for QoS 1."""
    return bytes([PUBACK, 0x02, (packet_id >> 8) & 0xFF, packet_id & 0xFF])


def build_suback(packet_id: int, granted_qos: list[int]) -> bytes:
    """SUBACK acknowledging subscriptions."""
    payload = bytes([SUBACK, 2 + len(granted_qos), (packet_id >> 8) & 0xFF, packet_id & 0xFF])
    return payload + bytes(granted_qos)


def build_pingresp() -> bytes:
    """PINGRESP."""
    return bytes([PINGRESP, 0x00])
