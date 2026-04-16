/*
  Starter sketch for future M5Stack integration.
  Idea:
  1. Connect to Wi-Fi.
  2. Subscribe to an MQTT topic like honeypot/alerts.
  3. Show alert type + source IP on screen.

  This file is intentionally simple because the main project can already run
  without hardware. Add your Wi-Fi SSID/password and broker info later.
*/

#include <M5Stack.h>

void setup() {
  M5.begin();
  M5.Power.begin();
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(WHITE);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(20, 20);
  M5.Lcd.println("MQTT Honeypot");
  M5.Lcd.setCursor(20, 60);
  M5.Lcd.println("M5Stack ready");
  M5.Lcd.setCursor(20, 100);
  M5.Lcd.println("Waiting for alerts...");
}

void loop() {
  // Later: poll or subscribe to alerts here.
  delay(1000);
}
