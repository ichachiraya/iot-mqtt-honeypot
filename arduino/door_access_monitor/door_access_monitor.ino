/*
 * Door / Access Monitor — M5Stack + MQTT
 * ----------------------------------------
 * จำลองเป็น door sensor:
 *   - กดปุ่ม A → ประตูเปิด  (OPEN)
 *   - กดปุ่ม B → ประตูปิด   (CLOSED)
 *
 * Topics:
 *   /factory/door/status     → "OPEN" | "CLOSED"
 *   /factory/door/heartbeat  → "online"  (ทุก 10 วินาที)
 *
 * Libraries ที่ต้องติดตั้ง:
 *   - M5Stack   (Board Manager → M5Stack)
 *   - PubSubClient  (Library Manager)
 */

#include <M5Stack.h>
#include <WiFi.h>
#include <PubSubClient.h>

// ─── WiFi Configuration ────────────────────────────────────────────
const char* WIFI_SSID     = "siam fc_2.4G";      // ← เปลี่ยนเป็น SSID ของคุณ
const char* WIFI_PASSWORD = "liverpool";   // ← เปลี่ยนเป็น Password ของคุณ

// ─── MQTT Configuration ────────────────────────────────────────────
const char* MQTT_BROKER   = "192.168.1.104";        // ← เปลี่ยนเป็น IP ของ MQTT broker
const int   MQTT_PORT     = 1883;
const char* MQTT_CLIENT   = "door_monitor_02";

const char* TOPIC_STATUS    = "/factory/door/status";
const char* TOPIC_HEARTBEAT = "/factory/door/heartbeat";

// ─── Timing ────────────────────────────────────────────────────────
const unsigned long HEARTBEAT_INTERVAL_MS = 10000;  // 10 วินาที

// ─── Global Objects ────────────────────────────────────────────────
WiFiClient   wifiClient;
PubSubClient mqttClient(wifiClient);

unsigned long lastHeartbeatTime = 0;

// ─── Door State ────────────────────────────────────────────────────
enum DoorState { DOOR_CLOSED, DOOR_OPEN };
DoorState currentDoor  = DOOR_CLOSED;
DoorState previousDoor = DOOR_CLOSED;

// เก็บเวลา (millis) ที่เปลี่ยนสถานะล่าสุด
unsigned long lastChangeMillis = 0;
// จำนวนวินาทีตั้งแต่บูต ณ เวลาเปลี่ยนสถานะ
unsigned long lastChangeSec    = 0;

// ─── Colors ────────────────────────────────────────────────────────
#define CLR_BG         TFT_BLACK
#define CLR_TITLE      TFT_CYAN
#define CLR_OPEN       0xFDA0   // สีส้มอ่อน
#define CLR_CLOSED     TFT_GREEN
#define CLR_LABEL      TFT_WHITE
#define CLR_VALUE      TFT_YELLOW
#define CLR_WIFI_OK    TFT_GREEN
#define CLR_WIFI_ERR   TFT_RED
#define CLR_MQTT_OK    TFT_GREEN
#define CLR_MQTT_ERR   TFT_RED
#define CLR_BTN_HINT   TFT_LIGHTGREY

// ════════════════════════════════════════════════════════════════════
//  WiFi helpers
// ════════════════════════════════════════════════════════════════════

void connectWiFi() {
  Serial.printf("[WiFi] Connecting to %s ", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int retries = 0;
  while (WiFi.status() != WL_CONNECTED && retries < 40) {  // ~20 s timeout
    delay(500);
    Serial.print(".");
    retries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[WiFi] Connected — IP: %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\n[WiFi] Connection FAILED — will retry later");
  }
}

void ensureWiFi() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WiFi] Disconnected — reconnecting...");
    connectWiFi();
  }
}

// ════════════════════════════════════════════════════════════════════
//  MQTT helpers
// ════════════════════════════════════════════════════════════════════

void connectMQTT() {
  Serial.printf("[MQTT] Connecting to %s:%d as '%s'...\n",
                MQTT_BROKER, MQTT_PORT, MQTT_CLIENT);

  int retries = 0;
  while (!mqttClient.connected() && retries < 5) {
    if (mqttClient.connect(MQTT_CLIENT)) {
      Serial.println("[MQTT] Connected ✓");
      return;
    }
    Serial.printf("[MQTT] Failed (rc=%d) — retrying in 2 s\n", mqttClient.state());
    delay(2000);
    retries++;
  }

  if (!mqttClient.connected()) {
    Serial.println("[MQTT] Could not connect — will retry next cycle");
  }
}

void ensureMQTT() {
  if (!mqttClient.connected()) {
    connectMQTT();
  }
}

// ════════════════════════════════════════════════════════════════════
//  Time formatting helper
// ════════════════════════════════════════════════════════════════════

// แปลง millis เป็น HH:MM:SS (นับจากบูต — ไม่มี RTC)
void formatUptime(unsigned long totalSec, char* buf, size_t len) {
  unsigned long h = totalSec / 3600;
  unsigned long m = (totalSec % 3600) / 60;
  unsigned long s = totalSec % 60;
  snprintf(buf, len, "%02lu:%02lu:%02lu", h, m, s);
}

// ════════════════════════════════════════════════════════════════════
//  Display helpers
// ════════════════════════════════════════════════════════════════════

void drawHeader() {
  M5.Lcd.fillRect(0, 0, 320, 40, TFT_NAVY);
  M5.Lcd.setTextColor(CLR_TITLE, TFT_NAVY);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(40, 10);
  M5.Lcd.print("Door/Access Monitor");
}

void drawConnectionStatus() {
  int y = 45;
  M5.Lcd.fillRect(0, y, 320, 20, CLR_BG);
  M5.Lcd.setTextSize(1);

  // WiFi
  M5.Lcd.setCursor(10, y + 4);
  if (WiFi.status() == WL_CONNECTED) {
    M5.Lcd.setTextColor(CLR_WIFI_OK, CLR_BG);
    M5.Lcd.printf("WiFi: OK (%s)", WiFi.localIP().toString().c_str());
  } else {
    M5.Lcd.setTextColor(CLR_WIFI_ERR, CLR_BG);
    M5.Lcd.print("WiFi: DISCONNECTED");
  }

  // MQTT
  M5.Lcd.setCursor(230, y + 4);
  if (mqttClient.connected()) {
    M5.Lcd.setTextColor(CLR_MQTT_OK, CLR_BG);
    M5.Lcd.print("MQTT: OK");
  } else {
    M5.Lcd.setTextColor(CLR_MQTT_ERR, CLR_BG);
    M5.Lcd.print("MQTT: OFF");
  }
}

void drawDoorStatus() {
  int startY = 75;

  // Clear data area (leave button hints at bottom)
  M5.Lcd.fillRect(0, startY, 320, 140, CLR_BG);

  // ── Door icon / status ──
  bool isOpen = (currentDoor == DOOR_OPEN);
  uint16_t statusColor = isOpen ? CLR_OPEN : CLR_CLOSED;
  const char* statusText = isOpen ? "OPEN" : "CLOSED";

  // Big status box
  int boxX = 40, boxY = startY + 5, boxW = 240, boxH = 60;
  M5.Lcd.drawRoundRect(boxX, boxY, boxW, boxH, 8, statusColor);
  M5.Lcd.drawRoundRect(boxX + 1, boxY + 1, boxW - 2, boxH - 2, 7, statusColor);

  M5.Lcd.setTextSize(4);
  M5.Lcd.setTextColor(statusColor, CLR_BG);

  // Center the text
  int textW = strlen(statusText) * 24;  // approx width at size 4
  int textX = boxX + (boxW - textW) / 2;
  M5.Lcd.setCursor(textX, boxY + 16);
  M5.Lcd.print(statusText);

  // ── Last change time ──
  M5.Lcd.setTextSize(2);
  M5.Lcd.setTextColor(CLR_LABEL, CLR_BG);
  M5.Lcd.setCursor(10, startY + 80);
  M5.Lcd.print("Last change:");

  char timeBuf[16];
  if (lastChangeMillis == 0) {
    snprintf(timeBuf, sizeof(timeBuf), "--:--:--");
  } else {
    formatUptime(lastChangeSec, timeBuf, sizeof(timeBuf));
  }
  M5.Lcd.setTextColor(CLR_VALUE, CLR_BG);
  M5.Lcd.setCursor(170, startY + 80);
  M5.Lcd.print(timeBuf);

  // ── Uptime ──
  char uptimeBuf[16];
  formatUptime(millis() / 1000, uptimeBuf, sizeof(uptimeBuf));
  M5.Lcd.setTextColor(CLR_LABEL, CLR_BG);
  M5.Lcd.setCursor(10, startY + 108);
  M5.Lcd.print("Uptime:");
  M5.Lcd.setTextColor(CLR_VALUE, CLR_BG);
  M5.Lcd.setCursor(170, startY + 108);
  M5.Lcd.print(uptimeBuf);
}

void drawButtonHints() {
  int y = 222;
  M5.Lcd.fillRect(0, y, 320, 18, CLR_BG);
  M5.Lcd.setTextSize(1);
  M5.Lcd.setTextColor(CLR_BTN_HINT, CLR_BG);

  M5.Lcd.setCursor(30, y + 4);
  M5.Lcd.print("[A] OPEN");

  M5.Lcd.setCursor(230, y + 4);
  M5.Lcd.print("[B] CLOSE");
}

// ════════════════════════════════════════════════════════════════════
//  Publish door status
// ════════════════════════════════════════════════════════════════════

void publishDoorStatus() {
  const char* statusText = (currentDoor == DOOR_OPEN) ? "OPEN" : "CLOSED";

  Serial.printf("[DOOR] Status changed → %s\n", statusText);

  if (mqttClient.connected()) {
    mqttClient.publish(TOPIC_STATUS, statusText);
    Serial.printf("[MQTT] Published → %s = %s\n", TOPIC_STATUS, statusText);
  } else {
    Serial.println("[MQTT] Not connected — skipping publish");
  }
}

// ════════════════════════════════════════════════════════════════════
//  setup()
// ════════════════════════════════════════════════════════════════════

void setup() {
  M5.begin();            // LCD, Serial, Buttons
  M5.Power.begin();      // Battery / power management

  Serial.begin(115200);
  Serial.println("\n=== Door / Access Monitor ===");

  // ── Initial screen ──
  M5.Lcd.fillScreen(CLR_BG);
  drawHeader();

  M5.Lcd.setTextColor(CLR_LABEL, CLR_BG);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(30, 100);
  M5.Lcd.print("Connecting WiFi...");

  // ── Connect WiFi ──
  connectWiFi();

  // ── Setup MQTT ──
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  connectMQTT();

  // ── Draw full UI ──
  M5.Lcd.fillScreen(CLR_BG);
  drawHeader();
  drawConnectionStatus();
  drawDoorStatus();
  drawButtonHints();
}

// ════════════════════════════════════════════════════════════════════
//  loop()
// ════════════════════════════════════════════════════════════════════

void loop() {
  M5.update();           // Update button states
  mqttClient.loop();     // Keep MQTT alive

  // ── Button A → OPEN ──
  if (M5.BtnA.wasPressed()) {
    if (currentDoor != DOOR_OPEN) {
      previousDoor = currentDoor;
      currentDoor  = DOOR_OPEN;
      lastChangeMillis = millis();
      lastChangeSec    = lastChangeMillis / 1000;

      publishDoorStatus();
      drawDoorStatus();
      drawConnectionStatus();
    }
  }

  // ── Button B → CLOSED ──
  if (M5.BtnB.wasPressed()) {
    if (currentDoor != DOOR_CLOSED) {
      previousDoor = currentDoor;
      currentDoor  = DOOR_CLOSED;
      lastChangeMillis = millis();
      lastChangeSec    = lastChangeMillis / 1000;

      publishDoorStatus();
      drawDoorStatus();
      drawConnectionStatus();
    }
  }

  // ── Heartbeat every 10 s ──
  unsigned long now = millis();
  if (now - lastHeartbeatTime >= HEARTBEAT_INTERVAL_MS) {
    lastHeartbeatTime = now;

    // Ensure connections before heartbeat
    ensureWiFi();
    ensureMQTT();

    if (mqttClient.connected()) {
      mqttClient.publish(TOPIC_HEARTBEAT, "online");
      Serial.printf("[MQTT] Heartbeat → %s = online\n", TOPIC_HEARTBEAT);
    } else {
      Serial.println("[MQTT] Not connected — heartbeat skipped");
    }

    // Refresh connection indicators & uptime
    drawConnectionStatus();
    drawDoorStatus();
  }
}
