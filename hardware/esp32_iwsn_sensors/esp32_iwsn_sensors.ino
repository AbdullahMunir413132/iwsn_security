/*
 * ══════════════════════════════════════════════════════════════
 *          IWSN SECURITY — ESP32 Real Sensor Node v1.0
 * ══════════════════════════════════════════════════════════════
 * 
 *  Hardware:
 *    - ESP-WROOM-32D Microcontroller
 *    - SR04M-2 Waterproof Ultrasonic Sensor (UART Mode)
 *    - IR Obstacle Avoidance Sensor Module
 *    - Breadboard
 *
 *  Wiring (as connected by user):
 *    SR04M-2 TX  → ESP32 GPIO5   (Sensor sends data TO ESP32)
 *    SR04M-2 RX  → ESP32 GPIO18  (ESP32 sends commands TO sensor)
 *    SR04M-2 VCC → 5V (VIN)
 *    SR04M-2 GND → GND
 *
 *    IR OUT → ESP32 GPIO4
 *    IR VCC → 3.3V
 *    IR GND → GND
 *
 *  MQTT Topics Published:
 *    iwsn/sensors/ultrasonic/distance  — distance in cm (every 2s)
 *    iwsn/sensors/ir/obstacle          — obstacle detected (every 2s)
 *    iwsn/sensors/status/heartbeat     — node health (every 10s)
 *    iwsn/sensors/combined/reading     — combined reading (every 2s)
 *
 *  Libraries Required:
 *    - WiFi.h          (built-in with ESP32 board package)
 *    - PubSubClient.h  (install via Library Manager: "PubSubClient" by Nick O'Leary)
 *
 * ══════════════════════════════════════════════════════════════
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

// ══════════════════════════════════════════════════════════════
//  CONFIGURATION — EDIT THESE VALUES
// ══════════════════════════════════════════════════════════════

// WiFi Credentials
const char* WIFI_SSID     = "StormFiber-5658";
const char* WIFI_PASSWORD = "bossfamily";

// MQTT Broker (your Linux machine IP)
const char* MQTT_BROKER   = "192.168.1.20";
const int   MQTT_PORT     = 1883;
const char* MQTT_CLIENT   = "esp32_iwsn_node_01";

// ══════════════════════════════════════════════════════════════
//  PIN DEFINITIONS
// ══════════════════════════════════════════════════════════════

// SR04M-2 Ultrasonic Sensor (UART Mode)
//   Sensor TX → ESP32 RX pin (GPIO5)  — sensor sends data here
//   Sensor RX → ESP32 TX pin (GPIO18) — ESP32 sends trigger command here
#define SR04M2_RX_PIN  5    // ESP32 receives FROM sensor TX
#define SR04M2_TX_PIN  18   // ESP32 sends TO sensor RX

// IR Obstacle Avoidance Sensor
#define IR_SENSOR_PIN  4    // Digital input (LOW = obstacle detected)
#define IR_ACTIVE_LEVEL LOW  // Change to HIGH if your IR module is active-high
#define IR_SAMPLE_COUNT 7    // Odd number for majority vote filtering

// On-board LED for status indication
#define STATUS_LED     2    // Built-in LED on most ESP32 boards

// ══════════════════════════════════════════════════════════════
//  MQTT TOPICS
// ══════════════════════════════════════════════════════════════

#define TOPIC_ULTRASONIC  "iwsn/sensors/ultrasonic/distance"
#define TOPIC_IR          "iwsn/sensors/ir/obstacle"
#define TOPIC_HEARTBEAT   "iwsn/sensors/status/heartbeat"
#define TOPIC_COMBINED    "iwsn/sensors/combined/reading"

// ══════════════════════════════════════════════════════════════
//  TIMING CONFIGURATION
// ══════════════════════════════════════════════════════════════

#define SENSOR_INTERVAL_MS    2000    // Read sensors every 2 seconds
#define HEARTBEAT_INTERVAL_MS 10000   // Heartbeat every 10 seconds
#define WIFI_RETRY_DELAY_MS   500
#define MQTT_RETRY_DELAY_MS   5000

// ══════════════════════════════════════════════════════════════
//  GLOBAL OBJECTS
// ══════════════════════════════════════════════════════════════

WiFiClient espClient;
PubSubClient mqttClient(espClient);

// SR04M-2 uses Serial2 in UART mode (9600 baud by default)
HardwareSerial ultrasonicSerial(2);

// Timing variables
unsigned long lastSensorRead = 0;
unsigned long lastHeartbeat = 0;
unsigned long bootTime = 0;
uint32_t messageCount = 0;
uint32_t readingNumber = 0;

// Sensor data
float lastDistance = -1.0;
bool lastObstacle = false;

// ══════════════════════════════════════════════════════════════
//  WIFI SETUP
// ══════════════════════════════════════════════════════════════

void setupWiFi() {
  Serial.println();
  Serial.println("╔══════════════════════════════════════════╗");
  Serial.println("║   IWSN Security — ESP32 Sensor Node     ║");
  Serial.println("╚══════════════════════════════════════════╝");
  Serial.println();
  
  Serial.print("📡 Connecting to WiFi: ");
  Serial.println(WIFI_SSID);
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(WIFI_RETRY_DELAY_MS);
    Serial.print(".");
    attempts++;
    
    // Blink LED while connecting
    digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
    
    if (attempts > 60) {  // 30 seconds timeout
      Serial.println("\n❌ WiFi connection FAILED! Restarting...");
      ESP.restart();
    }
  }
  
  Serial.println();
  Serial.println("✅ WiFi Connected!");
  Serial.print("   IP Address: ");
  Serial.println(WiFi.localIP());
  Serial.print("   Signal (RSSI): ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");
  Serial.println();
  
  // Solid LED = connected
  digitalWrite(STATUS_LED, HIGH);
}

// ══════════════════════════════════════════════════════════════
//  MQTT SETUP & RECONNECT
// ══════════════════════════════════════════════════════════════

void setupMQTT() {
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setBufferSize(512);  // Larger buffer for JSON payloads
  Serial.print("🔗 MQTT Broker: ");
  Serial.print(MQTT_BROKER);
  Serial.print(":");
  Serial.println(MQTT_PORT);
}

void reconnectMQTT() {
  while (!mqttClient.connected()) {
    Serial.print("🔄 Connecting to MQTT broker...");
    
    // Create a unique client ID with chip ID
    String clientId = MQTT_CLIENT;
    clientId += "_";
    clientId += String(random(0xffff), HEX);
    
    if (mqttClient.connect(clientId.c_str())) {
      Serial.println(" ✅ Connected!");
      
      // Publish a birth announcement
      StaticJsonDocument<256> doc;
      doc["event"] = "node_online";
      doc["client_id"] = MQTT_CLIENT;
      doc["ip"] = WiFi.localIP().toString();
      doc["firmware"] = "IWSN_Sensor_v1.0";
      doc["sensors"][0] = "SR04M-2_Ultrasonic";
      doc["sensors"][1] = "IR_Obstacle";
      
      char buffer[256];
      serializeJson(doc, buffer);
      mqttClient.publish("iwsn/sensors/status/online", buffer, true);
      
      Serial.println("   📢 Birth announcement published");
      Serial.println();
    } else {
      Serial.print(" ❌ Failed (rc=");
      Serial.print(mqttClient.state());
      Serial.println("). Retrying in 5s...");
      
      // Blink LED on error
      for (int i = 0; i < 10; i++) {
        digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
        delay(MQTT_RETRY_DELAY_MS / 10);
      }
    }
  }
}

// ══════════════════════════════════════════════════════════════
//  SR04M-2 ULTRASONIC SENSOR (UART MODE)
// ══════════════════════════════════════════════════════════════
//
//  The SR04M-2 in UART mode (Mode 1):
//    - Send command byte 0xFF to trigger measurement
//    - Sensor responds with 4 bytes:
//        Byte 0: 0xFF (header)
//        Byte 1: Distance high byte
//        Byte 2: Distance low byte
//        Byte 3: Checksum (sum of bytes 0-2, lower 8 bits)
//    - Distance is in MILLIMETERS
//    - Baud rate: 9600
//
// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
// SR04M-2 ULTRASONIC SENSOR (UART Trigger Mode)
// ══════════════════════════════════════════════════════════════
bool readSR04Frame(uint8_t response[4], uint32_t timeoutMs) {
  unsigned long startWait = millis();

  while (millis() - startWait < timeoutMs) {
    if (ultrasonicSerial.available() > 0) {
      uint8_t b = ultrasonicSerial.read();

      if (b == 0xFF) {
        response[0] = b;

        unsigned long frameStart = millis();
        int idx = 1;
        while (idx < 4 && millis() - frameStart < 120) {
          if (ultrasonicSerial.available()) {
            response[idx++] = ultrasonicSerial.read();
          }
          delay(1);
        }

        if (idx == 4) {
          return true;
        }
      }
    }
    delay(1);
  }

  return false;
}

float readUltrasonicDistance() {
  // Clear stale bytes before a new request
  while (ultrasonicSerial.available()) ultrasonicSerial.read();

  uint8_t response[4];
  bool gotResponse = false;

  // Some SR04M-2 firmware variants trigger with 0x55, others with 0xFF.
  const uint8_t triggerCmds[2] = {0x55, 0xFF};
  for (int i = 0; i < 2; i++) {
    ultrasonicSerial.write(triggerCmds[i]);
    ultrasonicSerial.flush();

    if (readSR04Frame(response, 350)) {
      gotResponse = true;
      break;
    }
  }

  if (!gotResponse) {
    Serial.println(" ⚠️ SR04M-2: Timeout waiting for response (tried 0x55 and 0xFF)");
    return -1.0;
  }

  // Debug print first time or on error
  static bool debugOnce = true;
  if (debugOnce || response[0] != 0xFF) {
    Serial.print("SR04M-2 Raw: ");
    for (int i = 0; i < 4; i++) {
      Serial.print(response[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
    debugOnce = false;
  }

  // Validate header
  if (response[0] != 0xFF) {
    Serial.println(" ⚠️ SR04M-2: Invalid header (not 0xFF)");
    return -1.0;
  }

  // Checksum: 0xFF + high + low (lower 8 bits)
  uint8_t checksum = (response[0] + response[1] + response[2]) & 0xFF;
  if (checksum != response[3]) {
    Serial.println(" ⚠️ SR04M-2: Checksum mismatch");
    return -1.0;
  }

  uint16_t distance_mm = (response[1] << 8) | response[2];
  float distance_cm = distance_mm / 10.0;

  if (distance_cm < 2.0 || distance_cm > 600.0) {
    Serial.print(" ⚠️ SR04M-2: Out of range: ");
    Serial.print(distance_cm);
    Serial.println(" cm");
    return -1.0;
  }

  return distance_cm;
}

// ══════════════════════════════════════════════════════════════
//  IR OBSTACLE SENSOR
// ══════════════════════════════════════════════════════════════

bool readIRObstacle() {
  // Majority-vote digital filtering to avoid noisy/floating readings
  int activeCount = 0;

  for (int i = 0; i < IR_SAMPLE_COUNT; i++) {
    int rawValue = digitalRead(IR_SENSOR_PIN);
    if (rawValue == IR_ACTIVE_LEVEL) {
      activeCount++;
    }
    delay(2);
  }

  return (activeCount > (IR_SAMPLE_COUNT / 2));
}

// ══════════════════════════════════════════════════════════════
//  MQTT PUBLISHING
// ══════════════════════════════════════════════════════════════

void publishUltrasonicData(float distance_cm) {
  StaticJsonDocument<256> doc;
  
  doc["sensor_id"] = "SR04M-2";
  doc["type"] = "ultrasonic";
  doc["distance_cm"] = round(distance_cm * 100.0) / 100.0;  // 2 decimal places
  doc["unit"] = "cm";
  doc["reading_num"] = readingNumber;
  
  if (distance_cm < 0) {
    doc["status"] = "error";
    doc["distance_cm"] = nullptr;
  } else if (distance_cm < 20.0) {
    doc["status"] = "close_range";
    doc["alert"] = true;
  } else if (distance_cm > 400.0) {
    doc["status"] = "far_range";
  } else {
    doc["status"] = "valid";
  }
  
  doc["timestamp"] = millis() / 1000;
  
  char buffer[256];
  size_t len = serializeJson(doc, buffer);
  
  if (mqttClient.publish(TOPIC_ULTRASONIC, buffer)) {
    messageCount++;
    Serial.print("   📤 Ultrasonic: ");
    Serial.print(distance_cm, 1);
    Serial.println(" cm");
  }
}

void publishIRData(bool obstacleDetected) {
  StaticJsonDocument<200> doc;
  
  doc["sensor_id"] = "IR_OA_01";
  doc["type"] = "ir_obstacle";
  doc["obstacle_detected"] = obstacleDetected;
  doc["raw_value"] = obstacleDetected ? 0 : 1;
  doc["status"] = "active";
  doc["reading_num"] = readingNumber;
  doc["timestamp"] = millis() / 1000;
  
  char buffer[200];
  serializeJson(doc, buffer);
  
  if (mqttClient.publish(TOPIC_IR, buffer)) {
    messageCount++;
    Serial.print("   📤 IR Obstacle: ");
    Serial.println(obstacleDetected ? "⛔ DETECTED" : "✅ Clear");
  }
}

void publishCombinedReading(float distance_cm, bool obstacleDetected) {
  StaticJsonDocument<384> doc;
  
  doc["node_id"] = MQTT_CLIENT;
  doc["reading_num"] = readingNumber;
  doc["timestamp"] = millis() / 1000;
  
  JsonObject ultrasonic = doc.createNestedObject("ultrasonic");
  if (distance_cm >= 0) {
    ultrasonic["distance_cm"] = round(distance_cm * 100.0) / 100.0;
    ultrasonic["status"] = "valid";
  } else {
    ultrasonic["distance_cm"] = nullptr;
    ultrasonic["status"] = "error";
  }
  
  JsonObject ir = doc.createNestedObject("ir_obstacle");
  ir["detected"] = obstacleDetected;
  ir["raw"] = obstacleDetected ? 0 : 1;
  
  // Simple alert logic
  if (distance_cm > 0 && distance_cm < 15.0 && obstacleDetected) {
    doc["alert"] = "PROXIMITY_WARNING";
    doc["alert_level"] = "HIGH";
  } else if (obstacleDetected) {
    doc["alert"] = "OBSTACLE_DETECTED";
    doc["alert_level"] = "MEDIUM";
  } else {
    doc["alert"] = "NONE";
    doc["alert_level"] = "LOW";
  }
  
  char buffer[384];
  serializeJson(doc, buffer);
  
  if (mqttClient.publish(TOPIC_COMBINED, buffer)) {
    messageCount++;
  }
}

void publishHeartbeat() {
  StaticJsonDocument<300> doc;
  
  unsigned long uptime = (millis() - bootTime) / 1000;
  
  doc["node_id"] = MQTT_CLIENT;
  doc["type"] = "heartbeat";
  doc["uptime_seconds"] = uptime;
  doc["wifi_rssi"] = WiFi.RSSI();
  doc["wifi_ssid"] = WIFI_SSID;
  doc["free_heap"] = ESP.getFreeHeap();
  doc["ip_address"] = WiFi.localIP().toString();
  doc["messages_sent"] = messageCount;
  doc["readings_taken"] = readingNumber;
  doc["last_distance_cm"] = lastDistance;
  doc["last_obstacle"] = lastObstacle;
  doc["status"] = "online";
  doc["timestamp"] = millis() / 1000;
  
  char buffer[300];
  serializeJson(doc, buffer);
  
  if (mqttClient.publish(TOPIC_HEARTBEAT, buffer)) {
    messageCount++;
    Serial.print("   💓 Heartbeat #");
    Serial.print(messageCount);
    Serial.print(" | Uptime: ");
    Serial.print(uptime);
    Serial.print("s | RSSI: ");
    Serial.print(WiFi.RSSI());
    Serial.print("dBm | Heap: ");
    Serial.print(ESP.getFreeHeap());
    Serial.println(" bytes");
  }
}

// ══════════════════════════════════════════════════════════════
//  SETUP
// ══════════════════════════════════════════════════════════════

void setup() {
  // Initialize Serial Monitor
  Serial.begin(115200);
  delay(1000);
  
  Serial.println();
  Serial.println("═══════════════════════════════════════════════════");
  Serial.println("  IWSN Security — ESP32 Sensor Node Starting...   ");
  Serial.println("═══════════════════════════════════════════════════");
  Serial.println();
  
  // Initialize pins
  pinMode(STATUS_LED, OUTPUT);
  pinMode(IR_SENSOR_PIN, INPUT_PULLUP);
  
  // Initialize SR04M-2 UART (9600 baud, RX=GPIO5, TX=GPIO18)
  ultrasonicSerial.begin(9600, SERIAL_8N1, SR04M2_RX_PIN, SR04M2_TX_PIN);
  Serial.println("✅ SR04M-2 UART initialized (9600 baud)");
  Serial.print("   RX (from sensor TX): GPIO");
  Serial.println(SR04M2_RX_PIN);
  Serial.print("   TX (to sensor RX):   GPIO");
  Serial.println(SR04M2_TX_PIN);
  Serial.println();
  
  Serial.print("✅ IR Sensor on GPIO");
  Serial.println(IR_SENSOR_PIN);
  Serial.println();
  
  // Connect to WiFi
  setupWiFi();
  
  // Setup MQTT
  setupMQTT();
  
  bootTime = millis();
  
  Serial.println("═══════════════════════════════════════════════════");
  Serial.println("  🚀 Node Ready — Publishing sensor data via MQTT ");
  Serial.println("═══════════════════════════════════════════════════");
  Serial.println();
}

// ══════════════════════════════════════════════════════════════
//  MAIN LOOP
// ══════════════════════════════════════════════════════════════

void loop() {
  // Ensure WiFi is connected
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("⚠️  WiFi disconnected! Reconnecting...");
    setupWiFi();
  }
  
  // Ensure MQTT is connected
  if (!mqttClient.connected()) {
    reconnectMQTT();
  }
  mqttClient.loop();
  
  unsigned long now = millis();
  
  // ── Read and publish sensor data ──
  if (now - lastSensorRead >= SENSOR_INTERVAL_MS) {
    lastSensorRead = now;
    readingNumber++;
    
    Serial.print("── Reading #");
    Serial.print(readingNumber);
    Serial.println(" ─────────────────────────────");
    
    // Read ultrasonic distance
    float distance = readUltrasonicDistance();
    lastDistance = distance;
    publishUltrasonicData(distance);
    
    // Small delay between sensor reads
    delay(50);
    
    // Read IR obstacle sensor
    bool obstacle = readIRObstacle();
    lastObstacle = obstacle;
    publishIRData(obstacle);
    
    // Publish combined reading
    publishCombinedReading(distance, obstacle);
    
    Serial.println();
  }
  
  // ── Heartbeat ──
  if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
    lastHeartbeat = now;
    publishHeartbeat();
    Serial.println();
  }
}
