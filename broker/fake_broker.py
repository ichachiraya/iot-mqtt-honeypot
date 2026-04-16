"""
broker/fake_broker.py

Asyncio TCP server that listens on port 1883 and speaks enough of the
MQTT 3.1.1 protocol to accept connections from real clients (M5Stack,
paho-mqtt, mosquitto_pub, etc.).

For each packet received it calls backend.services.process_raw_event()
— the exact same pipeline as the HTTP /ingest endpoint.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from broker.broker_schemas import MqttConnect, MqttPublish, MqttSubscribe, MqttUnknown
from broker.mqtt_parser import (
    DISCONNECT,
    PINGREQ,
    build_connack,
    build_pingresp,
    build_puback,
    build_suback,
    parse,
)
from backend.schemas import RawEventIn
from backend.services import process_raw_event

MQTT_PORT = 1883
log = logging.getLogger("fake_broker")

SUSPICIOUS_USERNAMES = {"admin", "root", "test", "mqtt", "guest"}


class MqttClientSession:
    """Tracks state for one connected MQTT client."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader   = reader
        self.writer   = writer
        self.src_ip   = writer.get_extra_info("peername", ("0.0.0.0", 0))[0]
        self.client_id: str       = "unknown"
        self.username:  str | None = None
        self.connected: bool      = False

    # ── helpers ───────────────────────────────────────────────────────────────

    def _send(self, data: bytes) -> None:
        self.writer.write(data)

    def _ingest(self, action: str, topic: str, payload: str, qos: int = 0) -> None:
        """Push one event through the central analysis pipeline."""
        raw = RawEventIn(
            timestamp=datetime.now(timezone.utc),
            src_ip=self.src_ip,
            client_id=self.client_id,
            action=action,          # type: ignore[arg-type]
            topic=topic,
            payload=payload,
            qos=qos,
            username_used=self.username,
        )
        result = process_raw_event(raw)
        pred   = result.prediction
        log.info(
            "[%s] %s → %s (attack=%s, conf=%.2f)",
            self.src_ip,
            topic,
            pred.predicted_attack_type,
            pred.is_attack,
            pred.confidence,
        )

    # ── packet handlers ───────────────────────────────────────────────────────

    def handle_connect(self, packet: MqttConnect) -> None:
        self.client_id = packet.client_id
        self.username  = packet.username
        self.connected = True
        log.info("[%s] CONNECT client_id=%s user=%s", self.src_ip, self.client_id, self.username)
        self._send(build_connack(0))          # 0 = connection accepted
        # Label suspicious usernames as auth_fail so brute-force rules fire correctly
        is_suspicious = packet.username and packet.username.lower() in SUSPICIOUS_USERNAMES
        action = "auth_fail" if is_suspicious else "connect"
        self._ingest(action, "/mqtt/connect", f"CONNECT from {self.client_id}")

    def handle_publish(self, packet: MqttPublish) -> None:
        log.info("[%s] PUBLISH %s qos=%d", self.src_ip, packet.topic, packet.qos)
        if packet.qos == 1:
            self._send(build_puback(1))       # packet_id placeholder
        self._ingest("publish", packet.topic, packet.payload, packet.qos)

    def handle_subscribe(self, packet: MqttSubscribe) -> None:
        log.info("[%s] SUBSCRIBE %s", self.src_ip, packet.topics)
        granted = [0] * len(packet.topics)   # grant QoS 0 for all
        self._send(build_suback(packet.packet_id, granted))
        for topic in packet.topics:
            self._ingest("publish", topic, f"SUBSCRIBE to {topic}")

    def handle_unknown(self, packet: MqttUnknown) -> None:
        if packet.packet_type == PINGREQ:
            self._send(build_pingresp())
        elif packet.packet_type == DISCONNECT:
            log.info("[%s] DISCONNECT", self.src_ip)

    # ── main loop ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        log.info("[%s] New TCP connection", self.src_ip)
        try:
            while True:
                # Read up to 4096 bytes. Real MQTT clients rarely send more
                # than a few hundred bytes per packet for sensor data.
                data = await asyncio.wait_for(self.reader.read(4096), timeout=120)
                if not data:
                    break

                packet = parse(data)
                if packet is None:
                    log.warning("[%s] Unparseable packet (%d bytes)", self.src_ip, len(data))
                    continue

                if isinstance(packet, MqttConnect):
                    self.handle_connect(packet)
                elif isinstance(packet, MqttPublish):
                    self.handle_publish(packet)
                elif isinstance(packet, MqttSubscribe):
                    self.handle_subscribe(packet)
                elif isinstance(packet, MqttUnknown):
                    self.handle_unknown(packet)

                await self.writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            log.exception("[%s] Unexpected error: %s", self.src_ip, exc)
        finally:
            log.info("[%s] Connection closed", self.src_ip)
            self.writer.close()


async def _handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    session = MqttClientSession(reader, writer)
    await session.run()


async def start_mqtt_broker(host: str = "0.0.0.0", port: int = MQTT_PORT) -> None:
    """Start the fake MQTT broker. Intended to run as an asyncio background task."""
    try:
        server = await asyncio.start_server(_handle_client, host, port)
        print(f"[MQTT Broker] Fake MQTT broker listening on {host}:{port}")
        async with server:
            await server.serve_forever()
    except OSError as exc:
        print(f"[MQTT Broker] FAILED to bind port {port}: {exc}")
