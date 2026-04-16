"""
simulator/simulate.py

Simulates different traffic patterns to test the MQTT Honeypot.
Sends REAL MQTT packets to port 1883 using paho-mqtt.
"""
from __future__ import annotations

import argparse
import random
import string
import time
import threading

import paho.mqtt.client as mqtt

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883

def rand_payload(length: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def run_normal(count: int, delay: float) -> None:
    client = mqtt.Client(client_id=f"sensor_{random.randint(1, 10)}")
    client.username_pw_set("sensor_user", "pass")
    client.connect(BROKER_HOST, BROKER_PORT)
    client.loop_start()
    time.sleep(0.1)
    
    topics = ["/sensor/temp", "/sensor/humidity", "/device/status"]
    for i in range(count):
        topic = random.choice(topics)
        client.publish(topic, rand_payload(random.randint(20, 80)), qos=1)
        print(f"[{i+1}/{count}] [Normal] PUBLISH to {topic}")
        time.sleep(delay)
        
    client.disconnect()
    client.loop_stop()


def run_flood(count: int, delay: float) -> None:
    # Fixed client_id so all events accumulate in the same history window
    client = mqtt.Client(client_id="flood_attacker")
    client.username_pw_set("guest", "guest")
    client.connect(BROKER_HOST, BROKER_PORT)
    client.loop_start()
    time.sleep(0.1)
    
    count = count * 3  # Blast 3x more events since it's a flood
    delay = 0.05       # Extremely fast delay

    for i in range(count):
        client.publish("/sensor/temp", rand_payload(random.randint(40, 180)), qos=0)
        print(f"[{i+1}/{count}] [Flood] PUBLISH to /sensor/temp (Delay: {delay}s)")
        time.sleep(delay)
        
    client.disconnect()
    client.loop_stop()


def run_brute_force(count: int, delay: float) -> None:
    usernames = ["admin", "root", "mqtt", "test"]
    for i in range(count):
        user = random.choice(usernames)
        client = mqtt.Client(client_id=f"bf_{random.randint(1, 10)}")
        client.username_pw_set(user, "123456")
        
        try:
            client.connect(BROKER_HOST, BROKER_PORT)
            client.loop_start()
            time.sleep(0.1)
            # Try to publish to auth topic normally attackers do this to test
            client.publish("/auth", "login-attempt", qos=0)
            time.sleep(0.1)
            client.disconnect()
            client.loop_stop()
        except Exception:
            pass
        
        print(f"[{i+1}/{count}] [Brute Force] CONNECT attempt with user: {user}")
        time.sleep(delay)


def run_topic_scan(count: int, delay: float) -> None:
    client = mqtt.Client(client_id="scanner_1")
    client.username_pw_set("guest", "guest")
    client.connect(BROKER_HOST, BROKER_PORT)
    client.loop_start()
    time.sleep(0.1)
    
    topics = [
        "/factory/line1/temp", "/factory/line1/humidity",
        "/factory/line2/temp", "/factory/line2/humidity",
        "/admin/logs/recent", "/secret/config/backup",
        "/camera/frontdoor/status", "/plc/1/register/holding"
    ]
    
    for i in range(count):
        topic = random.choice(topics)
        client.publish(topic, rand_payload(random.randint(20, 60)), qos=1)
        print(f"[{i+1}/{count}] [Topic Scan] PUBLISH to {topic}")
        time.sleep(delay)
        
    client.disconnect()
    client.loop_stop()


def run_oversized_payload(count: int, delay: float) -> None:
    client = mqtt.Client(client_id="payload_abuse_1")
    client.username_pw_set("uploader", "pass")
    client.connect(BROKER_HOST, BROKER_PORT)
    client.loop_start()
    time.sleep(0.1)
    
    for i in range(count):
        payload = rand_payload(random.randint(1200, 2500))
        client.publish("/upload/blob", payload, qos=1)
        print(f"[{i+1}/{count}] [Oversized] PUBLISH {len(payload)} bytes to /upload/blob")
        time.sleep(delay)
        
    client.disconnect()
    client.loop_stop()


MODE_MAP = {
    "normal": run_normal,
    "flood": run_flood,
    "brute_force": run_brute_force,
    "topic_scan": run_topic_scan,
    "oversized_payload": run_oversized_payload,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send real MQTT traffic to honeypot broker")
    parser.add_argument("mode", choices=list(MODE_MAP.keys()), help="Traffic scenario to simulate")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.2)
    args = parser.parse_args()

    print(f"Connecting to MQTT Broker at {BROKER_HOST}:{BROKER_PORT}...")
    try:
        MODE_MAP[args.mode](args.count, args.delay)
        print("Done.")
    except ConnectionRefusedError:
        print("ERROR: Connection refused. Is the honeypot MQTT broker running on port 1883?")
