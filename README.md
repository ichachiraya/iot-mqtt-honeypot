# MQTT Honeypot & IoT Attack Monitor

An interactive, real-time MQTT Honeypot designed to detect, classify, and visualize IoT-based cyber attacks. This system acts as a decoy MQTT broker, seamlessly capturing telemetry from legitimate IoT devices (like M5Stack/Arduino sensors) while simultaneously flagging and analyzing malicious traffic from simulated attackers.

![Dashboard Preview](dashboard/assets/preview.png) *(Note: Place a screenshot of your dashboard here)*

## 🌟 Key Features

- **Fake MQTT Broker:** Listens on port `1883` to capture raw MQTT traffic directly.
- **Real-Time Attack Detection (Rule-Based):** Analyzes connection rates, payload sizes, and topic scanning behaviors to detect attacks like `flood`, `brute_force`, `topic_scan`, and `oversized_payload`.
- **Dynamic Device Auto-Discovery:** Automatically detects normal IoT devices (e.g., Door Monitors, Vibration Sensors) and renders them in the interactive Device Panel.
- **Live Dashboard:** Built with Server-Sent Events (SSE) to push live traffic, payload previews, and security alerts to the browser instantly without polling.
- **Hardware Integration Ready:** Plug-and-play compatible with real Arduino/ESP32 devices out of the box.

## 🏗️ System Architecture

1. **Frontend (Dashboard):** Pure HTML/CSS/JS. Connects to the backend via SSE for live updates. Includes syntax-highlighted payload previews and visual gauges.
2. **Backend (FastAPI):** Python-based REST API and SSE stream provider. Also hosts the internal Fake Broker on a background thread.
3. **Database (SQLite):** Lightweight, persistent storage for raw events, feature extractions, and prediction results.
4. **Simulator:** A Python script to generate both benign traffic and various MQTT attack vectors.

## 🚀 Quick Start

### 1. Install Dependencies
Ensure you have Python 3.9+ installed.
```bash
pip install -r requirements.txt
```

### 2. Start the Backend Server
Run the FastAPI backend. This automatically starts the Web Server on port `8000` and the Fake MQTT Broker on port `1883`.
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### 3. Open the Dashboard
Navigate to the following URL in your web browser:
```text
http://localhost:8000/dashboard/
```

## ⚔️ Simulating Attacks

You can use the included `simulate.py` script to test the honeypot's detection capabilities. Open a **new terminal window** and run any of the following commands:

**Normal Traffic:**
```bash
python simulator/simulate.py normal --count 20 --delay 0.5
```

**DDoS / Message Flood:**
```bash
python simulator/simulate.py flood --count 50 --delay 0.05
```

**Brute Force (Failed Auth):**
```bash
python simulator/simulate.py brute_force --count 15 --delay 0.1
```

**Topic Scanning (Reconnaissance):**
```bash
python simulator/simulate.py topic_scan --count 20 --delay 0.1
```

**Oversized Payload (Buffer Overflow Attempt):**
```bash
python simulator/simulate.py oversized_payload --count 10 --delay 0.2
```

## 🔌 Connecting Real IoT Hardware

To connect an ESP32, Arduino, or M5Stack to the honeypot:
1. Connect the board to the same WiFi network as the computer running the backend.
2. Set the `MQTT_BROKER` IP address in your `.ino` file to your computer's local IP (e.g., `192.168.1.x`).
3. Set the MQTT Port to `1883`.
4. Publish JSON payloads to any topic. The dashboard will automatically detect the new device and render a card for it!

---
*Developed as an Educational IoT Security Project.*
ค