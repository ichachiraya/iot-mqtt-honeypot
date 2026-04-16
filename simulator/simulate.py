from __future__ import annotations

import argparse
import random
import string
import time
from datetime import datetime, timezone

import requests

API_URL = "http://127.0.0.1:8000/ingest"


def rand_payload(length: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def normal_event() -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": f"192.168.1.{random.randint(10, 50)}",
        "client_id": f"sensor_{random.randint(1, 8)}",
        "action": random.choice(["connect", "publish", "publish"]),
        "topic": random.choice(["/sensor/temp", "/sensor/humidity", "/device/status"]),
        "payload": rand_payload(random.randint(20, 80)),
        "qos": random.choice([0, 1]),
        "username_used": "sensor_user",
    }


def flood_event() -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "10.0.0.99",
        "client_id": f"flood_{random.randint(1, 2)}",
        "action": random.choice(["connect", "publish", "publish", "publish"]),
        "topic": "/sensor/temp",
        "payload": rand_payload(random.randint(40, 180)),
        "qos": 0,
        "username_used": "guest",
    }


def brute_force_event() -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "10.0.0.55",
        "client_id": f"bf_{random.randint(1, 2)}",
        "action": "auth_fail",
        "topic": "/auth",
        "payload": "login-attempt",
        "qos": 0,
        "username_used": random.choice(["admin", "root", "mqtt", "test"]),
    }


def topic_scan_event() -> dict:
    topic = random.choice(
        [
            "/factory/line1/temp",
            "/factory/line1/humidity",
            "/factory/line2/temp",
            "/factory/line2/humidity",
            "/admin/logs/recent",
            "/secret/config/backup",
            "/camera/frontdoor/status",
            "/camera/backdoor/status",
            "/plc/1/register/holding",
            "/plc/2/register/coil",
        ]
    )
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "10.0.0.77",
        "client_id": "scanner_1",
        "action": "publish",
        "topic": topic,
        "payload": rand_payload(random.randint(20, 60)),
        "qos": 1,
        "username_used": "guest",
    }


def oversized_payload_event() -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "10.0.0.88",
        "client_id": "payload_abuse_1",
        "action": "publish",
        "topic": "/upload/blob",
        "payload": rand_payload(random.randint(1200, 2500)),
        "qos": 1,
        "username_used": "uploader",
    }


MODE_TO_GENERATOR = {
    "normal": normal_event,
    "flood": flood_event,
    "brute_force": brute_force_event,
    "topic_scan": topic_scan_event,
    "oversized_payload": oversized_payload_event,
}


def send(mode: str, count: int, delay: float) -> None:
    generator = MODE_TO_GENERATOR[mode]
    for index in range(count):
        payload = generator()
        response = requests.post(API_URL, json=payload, timeout=10)
        response.raise_for_status()
        body = response.json()
        prediction = body["prediction"]
        print(
            f"[{index + 1}/{count}] {payload['src_ip']} -> "
            f"{prediction['predicted_attack_type']} "
            f"(attack={prediction['is_attack']}, conf={prediction['confidence']})"
        )
        time.sleep(delay)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send synthetic events to the honeypot backend")
    parser.add_argument(
        "mode",
        choices=list(MODE_TO_GENERATOR.keys()),
        help="Traffic scenario to simulate",
    )
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.2)
    args = parser.parse_args()

    send(args.mode, args.count, args.delay)
