/*
 * ══════════════════════════════════════════════════════════════════════════
 *  IWSN SECURITY — ESP32 Quad-Sensor Node v2.0
 * ══════════════════════════════════════════════════════════════════════════
 *
 *  Hardware Components (4 sensors):
 *    - 2x SR04M-2 Waterproof Ultrasonic SONAR Sensors (UART Mode)
 *    - 2x IR Obstacle Avoidance Sensor Modules
 *    - ESP-WROOM-32D Microcontroller
 *
 *  Wiring Diagram:
 *  ┌──────────────────────────────────────────────────────────────────┐
 *  │ SONAR 1 (SR04M-2 A):                                           │
 *  │   TX  → ESP32 GPIO5   (Serial2 RX — sensor sends data)         │
 *  │   RX  → ESP32 GPIO18  (Serial2 TX — ESP32 sends trigger)       │
 *  │   VCC → 5V (VIN)                                                │
 *  │   GND → GND                                                     │
 *  │                                                                  │
 *  │ SONAR 2 (SR04M-2 B):                                           │
 *  │   TX  → ESP32 GPIO16  (Serial1 RX — sensor sends data)         │
 *  │   RX  → ESP32 GPIO17  (Serial1 TX — ESP32 sends trigger)       │
 *  │   VCC → 5V (VIN)                                                │
 *  │   GND → GND                                                     │
 *  │                                                                  │
 *  │ IR SENSOR 1:                                                     │
 *  │   OUT → ESP32 GPIO4   (Digital input, active LOW)               │
 *  │   VCC → 3.3V                                                    │
 *  │   GND → GND                                                     │
 *  │                                                                  │
 *  │ IR SENSOR 2:                                                     │
 *  │   OUT → ESP32 GPIO15  (Digital input, active LOW)               │
 *  │   VCC → 3.3V                                                    │
 *  │   GND → GND                                                     │
 *  └──────────────────────────────────────────────────────────────────┘
 *
 *  MQTT Topics Published:
 *    iwsn/sensors/{NODE_ID}/sonar_1     — ultrasonic distance (cm)
 *    iwsn/sensors/{NODE_ID}/sonar_2     — ultrasonic distance (cm)
 *    iwsn/sensors/{NODE_ID}/ir_1        — obstacle detection
 *    iwsn/sensors/{NODE_ID}/ir_2        — obstacle detection
 *    iwsn/sensors/{NODE_ID}/combined    — all 4 sensors combined
 *    iwsn/sensors/{NODE_ID}/heartbeat   — node health + diagnostics
 *    iwsn/sensors/{NODE_ID}/online      — birth announcement (retained)
 *
 *  Libraries Required:
 *    - WiFi.h          (ESP32 board package)
 *    - PubSubClient.h  (Library Manager: "PubSubClient" by Nick O'Leary)
 *    - ArduinoJson.h   (Library Manager: "ArduinoJson" by Benoit Blanchon)
 *    - time.h          (ESP32 SNTP for NTP timestamps)
 *
 *  Credentials:
 *    Copy credentials.h.example → credentials.h and fill in your values.
 *
 * ══════════════════════════════════════════════════════════════════════════
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h>
#include "credentials.h"

// ══════════════════════════════════════════════════════════════
//  PIN DEFINITIONS
// ══════════════════════════════════════════════════════════════

// SONAR 1 — SR04M-2 (UART on Serial2)
#define SONAR1_RX_PIN   5     // ESP32 receives FROM sensor TX
#define SONAR1_TX_PIN   18    // ESP32 sends TO sensor RX

// SONAR 2 — SR04M-2 (UART on Serial1)
#define SONAR2_RX_PIN   16    // ESP32 receives FROM sensor TX
#define SONAR2_TX_PIN   17    // ESP32 sends TO sensor RX

// IR Sensor 1
#define IR1_PIN         4     // Digital input (LOW = obstacle)
#define IR1_ACTIVE      LOW

// IR Sensor 2
#define IR2_PIN         15    // Digital input (LOW = obstacle)
#define IR2_ACTIVE      LOW

// IR noise filtering: majority vote over N samples
#define IR_SAMPLE_COUNT 7

// Status LED
#define STATUS_LED      2

// ══════════════════════════════════════════════════════════════
//  MQTT TOPIC CONSTRUCTION
// ══════════════════════════════════════════════════════════════

// Topics are built at runtime from NODE_ID (defined in credentials.h)
static char TOPIC_SONAR1[64];
static char TOPIC_SONAR2[64];
static char TOPIC_IR1[64];
static char TOPIC_IR2[64];
static char TOPIC_COMBINED[64];
static char TOPIC_HEARTBEAT[64];
static char TOPIC_ONLINE[64];

void buildTopics() {
    snprintf(TOPIC_SONAR1,    sizeof(TOPIC_SONAR1),    "iwsn/sensors/%s/sonar_1",   NODE_ID);
    snprintf(TOPIC_SONAR2,    sizeof(TOPIC_SONAR2),    "iwsn/sensors/%s/sonar_2",   NODE_ID);
    snprintf(TOPIC_IR1,       sizeof(TOPIC_IR1),       "iwsn/sensors/%s/ir_1",      NODE_ID);
    snprintf(TOPIC_IR2,       sizeof(TOPIC_IR2),       "iwsn/sensors/%s/ir_2",      NODE_ID);
    snprintf(TOPIC_COMBINED,  sizeof(TOPIC_COMBINED),  "iwsn/sensors/%s/combined",  NODE_ID);
    snprintf(TOPIC_HEARTBEAT, sizeof(TOPIC_HEARTBEAT), "iwsn/sensors/%s/heartbeat", NODE_ID);
    snprintf(TOPIC_ONLINE,    sizeof(TOPIC_ONLINE),    "iwsn/sensors/%s/online",    NODE_ID);
}

// ══════════════════════════════════════════════════════════════
//  TIMING
// ══════════════════════════════════════════════════════════════

#define SENSOR_INTERVAL_MS    2000    // Read all 4 sensors every 2 seconds
#define HEARTBEAT_INTERVAL_MS 10000   // Heartbeat every 10 seconds
#define NTP_SYNC_INTERVAL_MS  3600000 // Re-sync NTP every hour
#define WIFI_RETRY_DELAY_MS   500
#define MQTT_RETRY_DELAY_MS   5000

// NTP Configuration
#define NTP_SERVER    "pool.ntp.org"
#define NTP_OFFSET    0               // UTC offset in seconds (adjust for your timezone)
#define NTP_DAYLIGHT  0               // Daylight savings offset

// ══════════════════════════════════════════════════════════════
//  GLOBAL OBJECTS
// ══════════════════════════════════════════════════════════════

WiFiClient espClient;
PubSubClient mqttClient(espClient);

// SONAR serial ports
HardwareSerial sonar1Serial(2);   // Serial2: GPIO5 (RX), GPIO18 (TX)
HardwareSerial sonar2Serial(1);   // Serial1: GPIO16 (RX), GPIO17 (TX)

// Timing
unsigned long lastSensorRead = 0;
unsigned long lastHeartbeat  = 0;
unsigned long bootTime       = 0;

// Counters
uint32_t messageCount  = 0;
uint32_t readingNumber = 0;
uint32_t errorCount    = 0;

// Last sensor values (for heartbeat reporting)
float lastSonar1  = -1.0;
float lastSonar2  = -1.0;
bool  lastIR1     = false;
bool  lastIR2     = false;

// NTP time valid flag
bool ntpSynced = false;

// ══════════════════════════════════════════════════════════════
//  TIMESTAMP — NTP-synced ISO 8601
// ══════════════════════════════════════════════════════════════

void setupNTP() {
    configTime(NTP_OFFSET, NTP_DAYLIGHT, NTP_SERVER, "time.nist.gov");
    Serial.print("  Syncing NTP...");
    struct tm timeinfo;
    int retries = 0;
    while (!getLocalTime(&timeinfo) && retries < 20) {
        delay(500);
        Serial.print(".");
        retries++;
    }
    if (retries < 20) {
        ntpSynced = true;
        Serial.println(" OK");
        char buf[30];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
        Serial.print("  UTC Time: ");
        Serial.println(buf);
    } else {
        Serial.println(" FAILED (using millis fallback)");
    }
}

String getISO8601Timestamp() {
    struct tm timeinfo;
    if (ntpSynced && getLocalTime(&timeinfo)) {
        char buf[30];
        struct timeval tv;
        gettimeofday(&tv, NULL);
        int ms = tv.tv_usec / 1000;
        snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                 timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                 timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, ms);
        return String(buf);
    }
    // Fallback: millis since boot
    return String(millis());
}

// ══════════════════════════════════════════════════════════════
//  WiFi
// ══════════════════════════════════════════════════════════════

void setupWiFi() {
    Serial.println();
    Serial.println("  IWSN Security — ESP32 Quad-Sensor Node v2.0");
    Serial.println("  ============================================");
    Serial.println();
    Serial.print("  Connecting to WiFi: ");
    Serial.println(WIFI_SSID);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED) {
        delay(WIFI_RETRY_DELAY_MS);
        Serial.print(".");
        digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
        attempts++;
        if (attempts > 60) {
            Serial.println("\n  WiFi FAILED — restarting...");
            ESP.restart();
        }
    }

    Serial.println();
    Serial.print("  WiFi OK: ");
    Serial.print(WiFi.localIP());
    Serial.print(" (RSSI: ");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm)");
    digitalWrite(STATUS_LED, HIGH);
}

// ══════════════════════════════════════════════════════════════
//  MQTT
// ══════════════════════════════════════════════════════════════

void setupMQTT() {
    mqttClient.setServer(MQTT_BROKER_IP, MQTT_PORT);
    mqttClient.setBufferSize(512);
    Serial.print("  MQTT Broker: ");
    Serial.print(MQTT_BROKER_IP);
    Serial.print(":");
    Serial.println(MQTT_PORT);
}

void reconnectMQTT() {
    while (!mqttClient.connected()) {
        Serial.print("  MQTT connecting...");
        String clientId = String(NODE_ID) + "_" + String(random(0xffff), HEX);

        if (mqttClient.connect(clientId.c_str())) {
            Serial.println(" OK");

            // Birth announcement (retained)
            StaticJsonDocument<384> doc;
            doc["event"]     = "node_online";
            doc["node_id"]   = NODE_ID;
            doc["ip"]        = WiFi.localIP().toString();
            doc["firmware"]  = "IWSN_QuadSensor_v2.0";
            doc["timestamp"] = getISO8601Timestamp();
            JsonArray sensors = doc.createNestedArray("sensors");
            sensors.add("SR04M-2_A (sonar_1)");
            sensors.add("SR04M-2_B (sonar_2)");
            sensors.add("IR_OA_01 (ir_1)");
            sensors.add("IR_OA_02 (ir_2)");

            char buffer[384];
            serializeJson(doc, buffer);
            mqttClient.publish(TOPIC_ONLINE, buffer, true);  // retained
            Serial.println("  Birth announcement published");
        } else {
            Serial.print(" FAILED (rc=");
            Serial.print(mqttClient.state());
            Serial.println(") retrying in 5s...");
            for (int i = 0; i < 10; i++) {
                digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
                delay(MQTT_RETRY_DELAY_MS / 10);
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════
//  SR04M-2 SONAR READING (UART Trigger Mode)
// ══════════════════════════════════════════════════════════════
//
//  Protocol (Mode 1):
//    1. Send trigger byte (0x55 or 0xFF) to sensor RX
//    2. Sensor responds with 4 bytes:
//         [0] 0xFF (header)
//         [1] Distance high byte
//         [2] Distance low byte
//         [3] Checksum = (byte0 + byte1 + byte2) & 0xFF
//    3. Distance is in MILLIMETERS
//    4. Valid range: 20mm — 6000mm (2cm — 600cm)
//

bool readSR04Frame(HardwareSerial &serial, uint8_t response[4], uint32_t timeoutMs) {
    unsigned long startWait = millis();
    while (millis() - startWait < timeoutMs) {
        if (serial.available() > 0) {
            uint8_t b = serial.read();
            if (b == 0xFF) {
                response[0] = b;
                unsigned long frameStart = millis();
                int idx = 1;
                while (idx < 4 && millis() - frameStart < 120) {
                    if (serial.available()) {
                        response[idx++] = serial.read();
                    }
                    delay(1);
                }
                if (idx == 4) return true;
            }
        }
        delay(1);
    }
    return false;
}

float readSonar(HardwareSerial &serial, const char *label) {
    // Clear stale bytes
    while (serial.available()) serial.read();

    uint8_t response[4];
    bool gotResponse = false;

    // Try both trigger commands (firmware variants)
    const uint8_t triggers[] = {0x55, 0xFF};
    for (int i = 0; i < 2; i++) {
        serial.write(triggers[i]);
        serial.flush();
        if (readSR04Frame(serial, response, 350)) {
            gotResponse = true;
            break;
        }
    }

    if (!gotResponse) {
        errorCount++;
        return -1.0;
    }

    if (response[0] != 0xFF) {
        errorCount++;
        return -1.0;
    }

    uint8_t checksum = (response[0] + response[1] + response[2]) & 0xFF;
    if (checksum != response[3]) {
        errorCount++;
        return -1.0;
    }

    uint16_t distance_mm = (response[1] << 8) | response[2];
    float distance_cm = distance_mm / 10.0;

    if (distance_cm < 2.0 || distance_cm > 600.0) {
        return -1.0;  // Out of range (not an error, just invalid reading)
    }

    return distance_cm;
}

// ══════════════════════════════════════════════════════════════
//  IR OBSTACLE SENSOR — Majority Vote Filtering
// ══════════════════════════════════════════════════════════════

bool readIR(int pin, int activeLevel) {
    int activeCount = 0;
    for (int i = 0; i < IR_SAMPLE_COUNT; i++) {
        if (digitalRead(pin) == activeLevel) {
            activeCount++;
        }
        delay(2);
    }
    return (activeCount > (IR_SAMPLE_COUNT / 2));
}

// ══════════════════════════════════════════════════════════════
//  MQTT PUBLISHING — Individual Sensors
// ══════════════════════════════════════════════════════════════

void publishSonar(const char *topic, const char *sensorId, float distance_cm) {
    StaticJsonDocument<256> doc;
    doc["sensor_id"]   = sensorId;
    doc["type"]        = "ultrasonic";
    doc["reading_num"] = readingNumber;
    doc["timestamp"]   = getISO8601Timestamp();

    if (distance_cm >= 0) {
        doc["distance_cm"] = round(distance_cm * 100.0) / 100.0;
        doc["unit"]        = "cm";
        doc["status"]      = (distance_cm < 20.0) ? "close_range" : "valid";
        if (distance_cm < 15.0) doc["alert"] = true;
    } else {
        doc["distance_cm"] = (char*)NULL;
        doc["status"]      = "error";
    }

    char buffer[256];
    serializeJson(doc, buffer);
    if (mqttClient.publish(topic, buffer)) messageCount++;
}

void publishIR(const char *topic, const char *sensorId, bool obstacle) {
    StaticJsonDocument<200> doc;
    doc["sensor_id"]          = sensorId;
    doc["type"]               = "ir_obstacle";
    doc["obstacle_detected"]  = obstacle;
    doc["raw_value"]          = obstacle ? 0 : 1;
    doc["status"]             = "active";
    doc["reading_num"]        = readingNumber;
    doc["timestamp"]          = getISO8601Timestamp();

    char buffer[200];
    serializeJson(doc, buffer);
    if (mqttClient.publish(topic, buffer)) messageCount++;
}

// ══════════════════════════════════════════════════════════════
//  MQTT PUBLISHING — Combined Reading (all 4 sensors)
// ══════════════════════════════════════════════════════════════

void publishCombined(float s1, float s2, bool ir1, bool ir2) {
    StaticJsonDocument<512> doc;
    doc["node_id"]     = NODE_ID;
    doc["reading_num"] = readingNumber;
    doc["timestamp"]   = getISO8601Timestamp();

    // Sonar 1
    JsonObject sonar1 = doc.createNestedObject("sonar_1");
    if (s1 >= 0) {
        sonar1["distance_cm"] = round(s1 * 100.0) / 100.0;
        sonar1["status"]      = "valid";
    } else {
        sonar1["distance_cm"] = (char*)NULL;
        sonar1["status"]      = "error";
    }

    // Sonar 2
    JsonObject sonar2 = doc.createNestedObject("sonar_2");
    if (s2 >= 0) {
        sonar2["distance_cm"] = round(s2 * 100.0) / 100.0;
        sonar2["status"]      = "valid";
    } else {
        sonar2["distance_cm"] = (char*)NULL;
        sonar2["status"]      = "error";
    }

    // IR sensors
    JsonObject irObj1 = doc.createNestedObject("ir_1");
    irObj1["detected"] = ir1;
    irObj1["raw"]      = ir1 ? 0 : 1;

    JsonObject irObj2 = doc.createNestedObject("ir_2");
    irObj2["detected"] = ir2;
    irObj2["raw"]      = ir2 ? 0 : 1;

    // Alert logic — proximity warnings from either sonar
    bool close1 = (s1 > 0 && s1 < 15.0);
    bool close2 = (s2 > 0 && s2 < 15.0);
    bool anyObstacle = ir1 || ir2;

    if ((close1 || close2) && anyObstacle) {
        doc["alert"]       = "PROXIMITY_WARNING";
        doc["alert_level"] = "HIGH";
    } else if (anyObstacle) {
        doc["alert"]       = "OBSTACLE_DETECTED";
        doc["alert_level"] = "MEDIUM";
    } else if (close1 || close2) {
        doc["alert"]       = "CLOSE_RANGE";
        doc["alert_level"] = "LOW";
    } else {
        doc["alert"]       = "NONE";
        doc["alert_level"] = "NORMAL";
    }

    char buffer[512];
    serializeJson(doc, buffer);
    if (mqttClient.publish(TOPIC_COMBINED, buffer)) messageCount++;
}

// ══════════════════════════════════════════════════════════════
//  HEARTBEAT — Node Health & Diagnostics
// ══════════════════════════════════════════════════════════════

void publishHeartbeat() {
    StaticJsonDocument<384> doc;
    unsigned long uptime = (millis() - bootTime) / 1000;

    doc["node_id"]         = NODE_ID;
    doc["type"]            = "heartbeat";
    doc["timestamp"]       = getISO8601Timestamp();
    doc["uptime_seconds"]  = uptime;
    doc["wifi_rssi"]       = WiFi.RSSI();
    doc["wifi_ssid"]       = WIFI_SSID;
    doc["free_heap"]       = ESP.getFreeHeap();
    doc["ip_address"]      = WiFi.localIP().toString();
    doc["messages_sent"]   = messageCount;
    doc["readings_taken"]  = readingNumber;
    doc["errors"]          = errorCount;
    doc["status"]          = "online";

    // Last sensor values
    JsonObject last = doc.createNestedObject("last_readings");
    last["sonar_1_cm"]    = lastSonar1;
    last["sonar_2_cm"]    = lastSonar2;
    last["ir_1_obstacle"] = lastIR1;
    last["ir_2_obstacle"] = lastIR2;

    char buffer[384];
    serializeJson(doc, buffer);
    if (mqttClient.publish(TOPIC_HEARTBEAT, buffer)) {
        messageCount++;
        Serial.print("  HB #");
        Serial.print(messageCount);
        Serial.print(" | Up:");
        Serial.print(uptime);
        Serial.print("s RSSI:");
        Serial.print(WiFi.RSSI());
        Serial.print("dBm Heap:");
        Serial.print(ESP.getFreeHeap());
        Serial.println("B");
    }
}

// ══════════════════════════════════════════════════════════════
//  SETUP
// ══════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println();
    Serial.println("  ================================================");
    Serial.println("  IWSN Security — ESP32 Quad-Sensor Node v2.0");
    Serial.println("  4 sensors: 2x SR04M-2 SONAR + 2x IR Obstacle");
    Serial.println("  ================================================");
    Serial.println();

    // Build MQTT topics from NODE_ID
    buildTopics();

    // Pins
    pinMode(STATUS_LED, OUTPUT);
    pinMode(IR1_PIN, INPUT_PULLUP);
    pinMode(IR2_PIN, INPUT_PULLUP);

    // Sonar 1 UART (Serial2)
    sonar1Serial.begin(9600, SERIAL_8N1, SONAR1_RX_PIN, SONAR1_TX_PIN);
    Serial.print("  Sonar 1 UART: RX=GPIO");
    Serial.print(SONAR1_RX_PIN);
    Serial.print(" TX=GPIO");
    Serial.println(SONAR1_TX_PIN);

    // Sonar 2 UART (Serial1)
    sonar2Serial.begin(9600, SERIAL_8N1, SONAR2_RX_PIN, SONAR2_TX_PIN);
    Serial.print("  Sonar 2 UART: RX=GPIO");
    Serial.print(SONAR2_RX_PIN);
    Serial.print(" TX=GPIO");
    Serial.println(SONAR2_TX_PIN);

    Serial.print("  IR 1: GPIO");
    Serial.print(IR1_PIN);
    Serial.print("  IR 2: GPIO");
    Serial.println(IR2_PIN);
    Serial.println();

    // WiFi
    setupWiFi();

    // NTP time sync
    setupNTP();

    // MQTT
    setupMQTT();

    bootTime = millis();

    Serial.println();
    Serial.println("  Node ready — publishing sensor data via MQTT");
    Serial.println("  ================================================");
    Serial.println();
}

// ══════════════════════════════════════════════════════════════
//  MAIN LOOP
// ══════════════════════════════════════════════════════════════

void loop() {
    // Reconnect WiFi if dropped
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("  WiFi lost — reconnecting...");
        setupWiFi();
        setupNTP();
    }

    // Reconnect MQTT if dropped
    if (!mqttClient.connected()) {
        reconnectMQTT();
    }
    mqttClient.loop();

    unsigned long now = millis();

    // ── Read and publish all 4 sensors ──
    if (now - lastSensorRead >= SENSOR_INTERVAL_MS) {
        lastSensorRead = now;
        readingNumber++;

        Serial.print("  #");
        Serial.print(readingNumber);
        Serial.print(" | ");

        // Read Sonar 1
        float s1 = readSonar(sonar1Serial, "S1");
        lastSonar1 = s1;
        publishSonar(TOPIC_SONAR1, "SR04M-2_A", s1);
        if (s1 >= 0) { Serial.print("S1:"); Serial.print(s1, 1); Serial.print("cm "); }
        else          { Serial.print("S1:ERR "); }

        delay(30);  // Brief pause between sonar readings to avoid crosstalk

        // Read Sonar 2
        float s2 = readSonar(sonar2Serial, "S2");
        lastSonar2 = s2;
        publishSonar(TOPIC_SONAR2, "SR04M-2_B", s2);
        if (s2 >= 0) { Serial.print("S2:"); Serial.print(s2, 1); Serial.print("cm "); }
        else          { Serial.print("S2:ERR "); }

        delay(20);

        // Read IR 1
        bool ir1 = readIR(IR1_PIN, IR1_ACTIVE);
        lastIR1 = ir1;
        publishIR(TOPIC_IR1, "IR_OA_01", ir1);
        Serial.print("IR1:");
        Serial.print(ir1 ? "OBS " : "CLR ");

        // Read IR 2
        bool ir2 = readIR(IR2_PIN, IR2_ACTIVE);
        lastIR2 = ir2;
        publishIR(TOPIC_IR2, "IR_OA_02", ir2);
        Serial.print("IR2:");
        Serial.println(ir2 ? "OBS" : "CLR");

        // Publish combined reading
        publishCombined(s1, s2, ir1, ir2);
    }

    // ── Heartbeat ──
    if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeat = now;
        publishHeartbeat();
    }
}
