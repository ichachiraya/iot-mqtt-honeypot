# MQTT Honeypot with Rule-Based + ML Detection

This is a starter project that follows the original plan:
- **Backend:** FastAPI + SQLite
- **ML:** scikit-learn RandomForest
- **Dashboard:** plain HTML/CSS/JS
- **Simulator:** sends synthetic MQTT-like events to backend
- **M5Stack:** placeholder for later hardware integration

## 1) Project structure

```text
mqtt-honeypot/
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── schemas.py
│   ├── database.py
│   ├── rules.py
│   ├── ml_model.py
│   └── artifacts/
│       └── model.pkl         # generated after training
├── simulator/
│   ├── simulate.py
│   ├── gen_dataset.py
│   ├── train_model.py
│   └── dataset.csv           # generated after dataset creation
├── dashboard/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── m5stack/
│   └── display.ino
├── requirements.txt
└── README.md
```

## 2) Data flow

### Raw input at runtime
The runtime input does **not** include `attack_type`.
The backend receives raw honeypot-style events, extracts features, and then predicts attack type.

### Training data
`attack_type` exists only in `dataset.csv` because the model needs labels for learning.

### Output
The backend produces:
- `is_attack`
- `predicted_attack_type`
- `confidence`
- `severity`
- `reason`

## 3) Schema separation

### `RawEventIn`
Used by `/ingest` input.

Example:
```json
{
  "src_ip": "10.0.0.77",
  "client_id": "scanner_1",
  "action": "publish",
  "topic": "/factory/line1/temp",
  "payload": "abc123",
  "qos": 1,
  "username_used": "guest"
}
```

### `FeatureEvent`
Created by backend from recent source history.

Fields:
- `connect_rate`
- `message_rate`
- `topic_count`
- `avg_payload_size`
- `failed_auth_count`

### `PredictionResult`
Final classification output from rule-based + ML combination.

## 4) Quick start

### Step A: install dependencies
```bash
pip install -r requirements.txt
```

### Step B: generate dataset
```bash
python simulator/gen_dataset.py
```

### Step C: train model
```bash
python simulator/train_model.py
```

### Step D: run backend
```bash
uvicorn backend.main:app --reload
```
Backend runs at:
- API: `http://127.0.0.1:8000`
- Swagger: `http://127.0.0.1:8000/docs`

### Step E: open dashboard
Open `dashboard/index.html` directly in your browser.

### Step F: send simulated traffic
Normal:
```bash
python simulator/simulate.py normal --count 20 --delay 0.3
```

Flood:
```bash
python simulator/simulate.py flood --count 30 --delay 0.05
```

Brute force:
```bash
python simulator/simulate.py brute_force --count 15 --delay 0.1
```

Topic scan:
```bash
python simulator/simulate.py topic_scan --count 20 --delay 0.1
```

Oversized payload:
```bash
python simulator/simulate.py oversized_payload --count 12 --delay 0.2
```

## 5) API endpoints

### `POST /ingest`
Receives a raw event, extracts features, classifies it, and stores everything in SQLite.

### `GET /events`
Returns recent events with features + predictions.

### `GET /alerts`
Returns recent attack alerts only.

### `GET /stats`
Returns summary numbers for the dashboard.

## 6) Suggested implementation order

### Day 1
- Run backend
- Confirm SQLite file is created
- Test `POST /ingest` from Swagger

### Day 2
- Use `simulate.py normal`
- Check `/events`

### Day 3
- Use `simulate.py flood`
- Check `/alerts`

### Day 4
- Tune thresholds in `backend/rules.py`

### Day 5-6
- Regenerate dataset and retrain model

### Day 7+
- Improve dashboard
- Add charts/filters
- Connect M5Stack later

## 7) Important note
This project is intentionally simple for a student demo.
It is not a full MQTT broker.
It acts like a lightweight honeypot-style event collector and classifier.
That makes it much easier to finish while still matching the project goal.
