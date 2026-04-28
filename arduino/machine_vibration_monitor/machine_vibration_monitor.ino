/*
 * Machine Vibration Monitor — M5Stack + IMU + MQTT
 * --------------------------------------------------
 * อ่านค่า accelerometer (X, Y, Z) จาก IMU ของ M5Stack
 * แล้วส่งผ่าน MQTT ไปยัง broker ทุก 3 วินาที
 *
 * Topics:
 *   /factory/machine/vibration  → JSON { "x": ..., "y": ..., "z": ... }
 *   /factory/machine/status     → "normal" | "alert"
 *
 * Libraries ที่ต้องติดตั้ง:
 *   - M5Stack  (Board Manager → M5Stack)
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
const char* MQTT_CLIENT   = "machine_monitor_01";

const char* TOPIC_VIBRATION = "/factory/machine/vibration";
const char* TOPIC_STATUS    = "/factory/machine/status";

// ─── Vibration Threshold ───────────────────────────────────────────
// magnitude = sqrt(x² + y² + z²)  — ค่าปกติขณะอยู่นิ่ง ≈ 1.0 g
// ถ้า magnitude เกิน threshold → alert
const float VIBRATION_THRESHOLD = 1.5;  // g  (ปรับได้ตามต้องการ)

// ─── Timing ────────────────────────────────────────────────────────
const unsigned long SEND_INTERVAL_MS = 5000;  // 3 วินาที

// ─── Global Objects ────────────────────────────────────────────────
WiFiClient   wifiClient;
PubSubClient mqttClient(wifiClient);

unsigned long lastSendTime = 0;

// ─── Colors ────────────────────────────────────────────────────────
#define CLR_BG        TFT_BLACK
#define CLR_TITLE     TFT_CYAN
#define CLR_NORMAL    TFT_GREEN
#define CLR_ALERT     TFT_RED
#define CLR_LABEL     TFT_WHITE
#define CLR_VALUE     TFT_YELLOW
#define CLR_WIFI_OK   TFT_GREEN
#define CLR_WIFI_ERR  TFT_RED
#define CLR_MQTT_OK   TFT_GREEN
#define CLR_MQTT_ERR  TFT_RED

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
  Serial.printf("[MQTT] Connecting to %s:%d as '%s'...\n", MQTT_BROKER, MQTT_PORT, MQTT_CLIENT);

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
//  Display helpers
// ════════════════════════════════════════════════════════════════════

void drawHeader() {
  M5.Lcd.fillRect(0, 0, 320, 40, TFT_NAVY);
  M5.Lcd.setTextColor(CLR_TITLE, TFT_NAVY);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(20, 10);
  M5.Lcd.print("Vibration Monitor");
}

void drawConnectionStatus() {
  int y = 45;
  M5.Lcd.fillRect(0, y, 320, 20, CLR_BG);
  M5.Lcd.setTextSize(1);

  // WiFi status
  M5.Lcd.setCursor(10, y + 4);
  if (WiFi.status() == WL_CONNECTED) {
    M5.Lcd.setTextColor(CLR_WIFI_OK, CLR_BG);
    M5.Lcd.printf("WiFi: OK (%s)", WiFi.localIP().toString().c_str());
  } else {
    M5.Lcd.setTextColor(CLR_WIFI_ERR, CLR_BG);
    M5.Lcd.print("WiFi: DISCONNECTED");
  }

  // MQTT status
  M5.Lcd.setCursor(230, y + 4);
  if (mqttClient.connected()) {
    M5.Lcd.setTextColor(CLR_MQTT_OK, CLR_BG);
    M5.Lcd.print("MQTT: OK");
  } else {
    M5.Lcd.setTextColor(CLR_MQTT_ERR, CLR_BG);
    M5.Lcd.print("MQTT: OFF");
  }
}

void drawVibrationData(float ax, float ay, float az, float mag, const char* status) {
  int startY = 75;

  // Clear data area
  M5.Lcd.fillRect(0, startY, 320, 165, CLR_BG);

  M5.Lcd.setTextSize(2);

  // ── Accelerometer values ──
  M5.Lcd.setTextColor(CLR_LABEL, CLR_BG);
  M5.Lcd.setCursor(10, startY);
  M5.Lcd.print("Accel X:");
  M5.Lcd.setTextColor(CLR_VALUE, CLR_BG);
  M5.Lcd.setCursor(180, startY);
  M5.Lcd.printf("%+.3f g", ax);

  M5.Lcd.setTextColor(CLR_LABEL, CLR_BG);
  M5.Lcd.setCursor(10, startY + 28);
  M5.Lcd.print("Accel Y:");
  M5.Lcd.setTextColor(CLR_VALUE, CLR_BG);
  M5.Lcd.setCursor(180, startY + 28);
  M5.Lcd.printf("%+.3f g", ay);

  M5.Lcd.setTextColor(CLR_LABEL, CLR_BG);
  M5.Lcd.setCursor(10, startY + 56);
  M5.Lcd.print("Accel Z:");
  M5.Lcd.setTextColor(CLR_VALUE, CLR_BG);
  M5.Lcd.setCursor(180, startY + 56);
  M5.Lcd.printf("%+.3f g", az);

  // ── Magnitude ──
  M5.Lcd.setTextColor(CLR_LABEL, CLR_BG);
  M5.Lcd.setCursor(10, startY + 92);
  M5.Lcd.print("Magnitude:");
  M5.Lcd.setTextColor(CLR_VALUE, CLR_BG);
  M5.Lcd.setCursor(180, startY + 92);
  M5.Lcd.printf("%.3f g", mag);

  // ── Divider ──
  M5.Lcd.drawFastHLine(10, startY + 120, 300, TFT_DARKGREY);

  // ── Status ──
  M5.Lcd.setTextSize(3);
  bool isAlert = (strcmp(status, "alert") == 0);
  uint16_t statusColor = isAlert ? CLR_ALERT : CLR_NORMAL;

  M5.Lcd.setTextColor(statusColor, CLR_BG);
  M5.Lcd.setCursor(60, startY + 132);
  M5.Lcd.printf("[ %s ]", status);
}

// ════════════════════════════════════════════════════════════════════
//  setup()
// ════════════════════════════════════════════════════════════════════

void setup() {
  M5.begin();            // LCD, Serial, Buttons
  M5.Power.begin();      // Battery / power management
  M5.IMU.Init();         // Initialize IMU (MPU6886 / SH200Q)

  Serial.begin(115200);
  Serial.println("\n=== Machine Vibration Monitor ===");

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

  // ── Redraw after connection ──
  M5.Lcd.fillScreen(CLR_BG);
  drawHeader();
  drawConnectionStatus();
}

// ════════════════════════════════════════════════════════════════════
//  loop()
// ════════════════════════════════════════════════════════════════════

void loop() {
  M5.update();           // Update button states
  mqttClient.loop();     // Keep MQTT alive

  unsigned long now = millis();
  if (now - lastSendTime < SEND_INTERVAL_MS) {
    return;              // ยังไม่ถึงเวลาส่ง
  }
  lastSendTime = now;

  // ── Ensure connections ──
  ensureWiFi();
  ensureMQTT();

  // ── Read IMU accelerometer ──
  float ax = 0.0, ay = 0.0, az = 0.0;
  M5.IMU.getAccelData(&ax, &ay, &az);   // ค่าหน่วย g

  // ── Calculate vibration magnitude ──
  float magnitude = sqrt(ax * ax + ay * ay + az * az);

  // ── Determine status ──
  const char* status = (magnitude > VIBRATION_THRESHOLD) ? "alert" : "normal";

  // ── Log to Serial ──
  Serial.printf("[DATA] X=%.3f  Y=%.3f  Z=%.3f  |mag|=%.3f  → %s\n",
                ax, ay, az, magnitude, status);

  // ── Update LCD ──
  drawConnectionStatus();
  drawVibrationData(ax, ay, az, magnitude, status);

  // ── Publish to MQTT (only if connected) ──
  if (mqttClient.connected()) {
    // Vibration payload (JSON)
    char vibPayload[128];
    snprintf(vibPayload, sizeof(vibPayload),
             "{\"x\":%.4f,\"y\":%.4f,\"z\":%.4f,\"magnitude\":%.4f}",
             ax, ay, az, magnitude);

    mqttClient.publish(TOPIC_VIBRATION, vibPayload);
    mqttClient.publish(TOPIC_STATUS, status);

    Serial.printf("[MQTT] Published → %s\n", TOPIC_VIBRATION);
    Serial.printf("[MQTT] Published → %s  = %s\n", TOPIC_STATUS, status);
  } else {
    Serial.println("[MQTT] Not connected — skipping publish");
  }
}
