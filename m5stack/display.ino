/*
  m5stack/display.ino

  M5Stack MQTT Motion Sensor Publisher
  ------------------------------------
  - Connects to WiFi
  - Connects to the fake MQTT broker on port 1883
  - Publishes motion/temperature events every 3 seconds
  - Shows connection status and last event on screen

  Libraries required (install via Arduino IDE Library Manager):
    - M5Stack          by M5Stack
    - PubSubClient     by Nick O'Leary
    - ArduinoJson      by Benoit Blanchon

  Board: M5Stack-Core-ESP32
  Upload speed: 921600
*/

#include <M5Stack.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

// ── Configuration ────────────────────────────────────────────────────────────
// TODO: Fill in your WiFi credentials and PC's local IP before flashing.

const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

// Your PC's local IP address (not 127.0.0.1 — find it with `ipconfig`)
const char* MQTT_BROKER   = "192.168.1.X";
const int   MQTT_PORT     = 1883;
const char* MQTT_CLIENT   = "m5stack_01";
const char* MQTT_USER     = "sensor_user";
const char* MQTT_PASS     = "sensor_pass";

// Topics
const char* TOPIC_MOTION  = "/sensor/motion";
const char* TOPIC_TEMP    = "/sensor/temp";
const char* TOPIC_STATUS  = "/device/status";

// Publish interval in milliseconds
const unsigned long PUBLISH_INTERVAL_MS = 3000;

// ── State ─────────────────────────────────────────────────────────────────────
WiFiClient   wifiClient;
PubSubClient mqttClient(wifiClient);

unsigned long lastPublish = 0;
int           msgCount    = 0;
bool          motionState = false;

// ── Display helpers ───────────────────────────────────────────────────────────

void drawHeader() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(CYAN);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(10, 5);
  M5.Lcd.println("MQTT Honeypot Node");
  M5.Lcd.drawLine(0, 28, 320, 28, DARKGREY);
}

void drawStatus(const char* label, const char* value, int y, uint16_t color) {
  M5.Lcd.setTextSize(1);
  M5.Lcd.setTextColor(DARKGREY);
  M5.Lcd.setCursor(10, y);
  M5.Lcd.print(label);
  M5.Lcd.setTextColor(color);
  M5.Lcd.println(value);
}

void updateDisplay() {
  drawStatus("WiFi:   ", WiFi.isConnected() ? WiFi.localIP().toString().c_str() : "connecting...",
             40, WiFi.isConnected() ? GREEN : YELLOW);
  drawStatus("Broker: ", mqttClient.connected() ? "Connected" : "Disconnected",
             60, mqttClient.connected() ? GREEN : RED);

  char buf[32];
  snprintf(buf, sizeof(buf), "%d msgs sent", msgCount);
  drawStatus("Stats:  ", buf, 80, WHITE);

  drawStatus("Motion: ", motionState ? "DETECTED" : "clear",
             110, motionState ? ORANGE : GREEN);
}

// ── WiFi ──────────────────────────────────────────────────────────────────────

void connectWifi() {
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.setCursor(10, 40);
  M5.Lcd.print("Connecting to WiFi...");

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    M5.Lcd.print(".");
  }

  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.println(" OK");
}

// ── MQTT ──────────────────────────────────────────────────────────────────────

void connectMqtt() {
  while (!mqttClient.connected()) {
    if (mqttClient.connect(MQTT_CLIENT, MQTT_USER, MQTT_PASS)) {
      // Announce device online
      mqttClient.publish(TOPIC_STATUS, "{\"status\": \"online\", \"device\": \"m5stack_01\"}");
    } else {
      delay(2000);
    }
  }
}

void publishSensorData() {
  // Toggle motion randomly to simulate real sensor
  motionState = (random(0, 4) == 0);   // ~25% chance of motion

  // Build JSON payload
  StaticJsonDocument<128> doc;
  doc["device"]    = MQTT_CLIENT;
  doc["motion"]    = motionState;
  doc["temp"]      = 25.0f + random(-30, 50) / 10.0f;
  doc["seq"]       = msgCount;

  char payload[128];
  serializeJson(doc, payload);

  mqttClient.publish(TOPIC_MOTION, payload, false);
  msgCount++;
}

// ── Arduino lifecycle ─────────────────────────────────────────────────────────

void setup() {
  M5.begin();
  M5.Power.begin();
  Serial.begin(115200);

  drawHeader();
  connectWifi();

  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setKeepAlive(30);
  connectMqtt();

  updateDisplay();
}

void loop() {
  M5.update();

  if (!WiFi.isConnected()) {
    connectWifi();
  }

  if (!mqttClient.connected()) {
    connectMqtt();
  }

  mqttClient.loop();

  unsigned long now = millis();
  if (now - lastPublish >= PUBLISH_INTERVAL_MS) {
    lastPublish = now;
    publishSensorData();
    updateDisplay();
  }
}
