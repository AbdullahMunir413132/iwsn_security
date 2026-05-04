/*
 * ══════════════════════════════════════════════════════════════════════════
 *  IWSN SECURITY — ESP32 Sensor Node 2
 * ══════════════════════════════════════════════════════════════════════════
 *
 *  Hardware Components (2 sensors):
 *    - 1x SR04M-2  Ultrasonic Distance Sensor
 *    - 1x Flying Fish IR Obstacle / Object Detector Sensor
 *    - ESP-WROOM-32D Microcontroller
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  WIRING DIAGRAM
 * ──────────────────────────────────────────────────────────────────────────
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐
 *  │  SR04M-2 Ultrasonic Distance Sensor                                 │
 *  │    VCC   → ESP32 5V  (Vin pin — SR04M-2 needs 5V)                 │
 *  │    GND   → ESP32 GND                                               │
 *  │    TRIG  → ESP32 GPIO5   (3.3V output is enough to trigger)        │
 *  │    ECHO  → ESP32 GPIO18  (SR04M-2 outputs 3.3V — safe direct)     │
 *  │                                                                     │
 *  │  NOTE: The SR04M-2 (waterproof) variant outputs 3.3V on ECHO,     │
 *  │  so no voltage divider is needed. Standard HC-SR04 outputs 5V     │
 *  │  on ECHO — for that, use a 1kΩ/2kΩ voltage divider to GPIO18.    │
 *  ├─────────────────────────────────────────────────────────────────────┤
 *  │  Flying Fish Object Detector (IR Obstacle)                         │
 *  │    VCC  → ESP32 3.3V   (or 5V — module works at both)             │
 *  │    GND  → ESP32 GND                                                │
 *  │    OUT  → ESP32 GPIO14  (LOW when object detected)                 │
 *  ├─────────────────────────────────────────────────────────────────────┤
 *  │  Built-in Status LED                                                │
 *  │    GPIO2 (on-board blue LED — no wiring needed)                    │
 *  └─────────────────────────────────────────────────────────────────────┘
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  MQTT Topics Published:
 *    iwsn/sensors/esp32_node_02/sonar      — distance (cm) + zone
 *    iwsn/sensors/esp32_node_02/object_1   — Flying Fish IR detector
 *    iwsn/sensors/esp32_node_02/combined   — all sensors combined
 *    iwsn/sensors/esp32_node_02/heartbeat  — node health + diagnostics
 *    iwsn/sensors/esp32_node_02/online     — birth announcement (retained)
 *
 *  Libraries Required (install via Arduino Library Manager):
 *    - WiFi.h         ESP32 board package (built-in)
 *    - Preferences.h  ESP32 board package (built-in)
 *    - PubSubClient   "PubSubClient" by Nick O'Leary
 *    - ArduinoJson    "ArduinoJson" by Benoit Blanchon (v6)
 *    - time.h         built-in
 *
 * ══════════════════════════════════════════════════════════════════════════
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h>

// ══════════════════════════════════════════════════════════════
//  HARDCODED CREDENTIALS (temporary — do not commit to git)
// ══════════════════════════════════════════════════════════════

#define HC_SSID        "OnePlus 8"
#define HC_PASS        "69000069"
#define HC_BROKER_IP   "10.136.166.1"
#define HC_BROKER_PORT 1883
#define HC_NODE_ID     "esp32_node_02"

// ══════════════════════════════════════════════════════════════
//  PIN DEFINITIONS
// ══════════════════════════════════════════════════════════════

// SR04M-2 Ultrasonic
#define SONAR_TRIG_PIN   5      // Trigger output to sensor
#define SONAR_ECHO_PIN   18     // Echo input from sensor

// Flying Fish IR Object Detector (active LOW)
#define OBJ_PIN          14
#define OBJ_ACTIVE       LOW
#define OBJ_SAMPLE_COUNT 7     // majority-vote debounce samples

// Status LED (built-in blue LED)
#define STATUS_LED       2

// ══════════════════════════════════════════════════════════════
//  SONAR SETTINGS
// ══════════════════════════════════════════════════════════════

#define SONAR_MAX_CM        400   // SR04M-2 max range ~400 cm
#define SONAR_MIN_CM        2     // SR04M-2 min range ~2 cm
#define SONAR_TIMEOUT_US    25000 // 25 ms = ~430 cm at 340 m/s (safe ceiling)
#define SONAR_SAMPLES       5     // median filter over N readings
#define SONAR_SAMPLE_DELAY  10    // ms between samples

// Zone thresholds (cm) — tweak to your environment
#define ZONE_NEAR_CM        30    // < 30 cm  → NEAR  (alert)
#define ZONE_MID_CM         80    // < 80 cm  → MID

// ══════════════════════════════════════════════════════════════
//  TIMING
// ══════════════════════════════════════════════════════════════

#define SENSOR_INTERVAL_MS    2000
#define HEARTBEAT_INTERVAL_MS 10000
#define MQTT_RETRY_DELAY_MS   5000

// NTP
#define NTP_SERVER   "pool.ntp.org"
#define NTP_OFFSET   0
#define NTP_DAYLIGHT 0

// ══════════════════════════════════════════════════════════════
//  GLOBAL STATE
// ══════════════════════════════════════════════════════════════

// MQTT topics
static char TOPIC_SONAR[64];
static char TOPIC_OBJ[64];
static char TOPIC_COMBINED[64];
static char TOPIC_HEARTBEAT[64];
static char TOPIC_ONLINE[64];

WiFiClient  espClient;
PubSubClient mqttClient(espClient);

unsigned long lastSensorRead = 0;
unsigned long lastHeartbeat  = 0;
unsigned long bootTime       = 0;

uint32_t messageCount  = 0;
uint32_t readingNumber = 0;
uint32_t errorCount    = 0;

float lastDistCm  = -1;
bool  lastObj     = false;
bool  ntpSynced   = false;

// ══════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════

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
    return String(millis());
}

const char* wifiStatusStr(wl_status_t s) {
    switch(s) {
        case WL_IDLE_STATUS:     return "IDLE";
        case WL_NO_SSID_AVAIL:   return "NO_SSID";
        case WL_CONNECTED:       return "CONNECTED";
        case WL_CONNECT_FAILED:  return "CONNECT_FAILED";
        case WL_CONNECTION_LOST: return "CONNECTION_LOST";
        case WL_DISCONNECTED:    return "DISCONNECTED";
        default:                 return "UNKNOWN";
    }
}

// ══════════════════════════════════════════════════════════════
//  SR04M-2 — MEDIAN-FILTERED DISTANCE READING
// ══════════════════════════════════════════════════════════════

// Single raw measurement — returns distance in cm, or -1 on timeout
float sonarReadRawCm() {
    // Send 10 µs trigger pulse
    digitalWrite(SONAR_TRIG_PIN, LOW);
    delayMicroseconds(2);
    digitalWrite(SONAR_TRIG_PIN, HIGH);
    delayMicroseconds(10);
    digitalWrite(SONAR_TRIG_PIN, LOW);

    // Measure echo pulse width
    long duration = pulseIn(SONAR_ECHO_PIN, HIGH, SONAR_TIMEOUT_US);
    if (duration == 0) return -1.0f;   // timeout / no echo

    float cm = (duration / 2.0f) / 29.1f;   // sound at ~340 m/s → 29.1 µs/cm
    if (cm < SONAR_MIN_CM || cm > SONAR_MAX_CM) return -1.0f;
    return cm;
}

// Comparison function for qsort (float array)
int cmpFloat(const void *a, const void *b) {
    float fa = *(float*)a, fb = *(float*)b;
    return (fa > fb) - (fa < fb);
}

// Returns median of SONAR_SAMPLES valid readings, or -1 if all timed out
float sonarReadMedianCm() {
    float samples[SONAR_SAMPLES];
    int valid = 0;
    for (int i = 0; i < SONAR_SAMPLES; i++) {
        float v = sonarReadRawCm();
        if (v > 0) samples[valid++] = v;
        delay(SONAR_SAMPLE_DELAY);
    }
    if (valid == 0) return -1.0f;
    qsort(samples, valid, sizeof(float), cmpFloat);
    return samples[valid / 2];   // median
}

// Zone label based on distance
const char* sonarZone(float cm) {
    if (cm < 0)             return "ERROR";
    if (cm < ZONE_NEAR_CM)  return "NEAR";
    if (cm < ZONE_MID_CM)   return "MID";
    return "FAR";
}

// ══════════════════════════════════════════════════════════════
//  FLYING FISH OD — MAJORITY VOTE
// ══════════════════════════════════════════════════════════════

bool readObjectDetector() {
    int active = 0;
    for (int i = 0; i < OBJ_SAMPLE_COUNT; i++) {
        if (digitalRead(OBJ_PIN) == OBJ_ACTIVE) active++;
        delay(2);
    }
    return (active > (OBJ_SAMPLE_COUNT / 2));
}

// ══════════════════════════════════════════════════════════════
//  WiFi
// ══════════════════════════════════════════════════════════════

void setupWiFi() {
    Serial.print("  Connecting to WiFi: ");
    Serial.println(HC_SSID);
    WiFi.disconnect(true);
    delay(300);
    WiFi.mode(WIFI_STA);
    WiFi.begin(HC_SSID, HC_PASS);

    int attempts = 0;
    wl_status_t lastSt = WL_IDLE_STATUS;
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
        wl_status_t st = WiFi.status();
        if (st != lastSt) {
            Serial.print("  [WiFi] "); Serial.println(wifiStatusStr(st));
            lastSt = st;
        } else {
            Serial.print(".");
        }
        if (++attempts > 120) {
            Serial.println("\n  WiFi failed — rebooting.");
            delay(2000);
            ESP.restart();
        }
    }
    Serial.println();
    Serial.print("  WiFi OK: "); Serial.print(WiFi.localIP());
    Serial.print("  RSSI: ");    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");
    digitalWrite(STATUS_LED, HIGH);
}

// ══════════════════════════════════════════════════════════════
//  NTP
// ══════════════════════════════════════════════════════════════

void setupNTP() {
    configTime(NTP_OFFSET, NTP_DAYLIGHT, NTP_SERVER, "time.nist.gov");
    Serial.print("  Syncing NTP...");
    struct tm timeinfo;
    int retries = 0;
    while (!getLocalTime(&timeinfo) && retries < 20) {
        delay(500); Serial.print("."); retries++;
    }
    if (retries < 20) {
        ntpSynced = true;
        char buf[30];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
        Serial.print(" OK — "); Serial.println(buf);
    } else {
        Serial.println(" FAILED (millis fallback)");
    }
}

// ══════════════════════════════════════════════════════════════
//  MQTT
// ══════════════════════════════════════════════════════════════

void reconnectMQTT() {
    while (!mqttClient.connected()) {
        Serial.print("  MQTT connecting...");
        String clientId = String(HC_NODE_ID) + "_" + String(random(0xffff), HEX);

        if (mqttClient.connect(clientId.c_str())) {
            Serial.println(" OK");

            StaticJsonDocument<256> doc;
            doc["event"]    = "node_online";
            doc["node_id"]  = HC_NODE_ID;
            doc["ip"]       = WiFi.localIP().toString();
            doc["firmware"] = "IWSN_Node2_v1.0";
            doc["timestamp"] = getISO8601Timestamp();
            JsonArray sensors = doc.createNestedArray("sensors");
            sensors.add("SR04M-2 (sonar)");
            sensors.add("FlyingFish_OD (object_1)");

            char buf[256];
            serializeJson(doc, buf);
            mqttClient.publish(TOPIC_ONLINE, buf, true);
            Serial.println("  Birth announcement published");
        } else {
            Serial.print(" FAILED rc="); Serial.print(mqttClient.state());
            Serial.println(" — retrying in 5s");
            for (int i = 0; i < 10; i++) {
                digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
                delay(MQTT_RETRY_DELAY_MS / 10);
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════
//  PUBLISHING
// ══════════════════════════════════════════════════════════════

void publishSonar(float distCm) {
    StaticJsonDocument<256> doc;
    doc["sensor_id"]   = "SR04M-2";
    doc["reading_num"] = readingNumber;
    doc["timestamp"]   = getISO8601Timestamp();

    if (distCm > 0) {
        doc["distance_cm"] = round(distCm * 10.0f) / 10.0f;
        doc["zone"]        = sonarZone(distCm);
        doc["status"]      = "valid";
        if (distCm < ZONE_NEAR_CM) doc["alert"] = "INTRUSION_NEAR";
    } else {
        doc["distance_cm"] = (char*)NULL;
        doc["zone"]        = "ERROR";
        doc["status"]      = "error";
        errorCount++;
    }

    char buf[256];
    serializeJson(doc, buf);
    if (mqttClient.publish(TOPIC_SONAR, buf)) messageCount++;
}

void publishObject(bool detected) {
    StaticJsonDocument<200> doc;
    doc["sensor_id"]       = "FF_OD_1";
    doc["type"]            = "ir_object_detector";
    doc["object_detected"] = detected;
    doc["raw_value"]       = detected ? 0 : 1;
    doc["status"]          = "active";
    doc["reading_num"]     = readingNumber;
    doc["timestamp"]       = getISO8601Timestamp();

    char buf[200];
    serializeJson(doc, buf);
    if (mqttClient.publish(TOPIC_OBJ, buf)) messageCount++;
}

void publishCombined(float distCm, bool obj) {
    StaticJsonDocument<512> doc;
    doc["node_id"]     = HC_NODE_ID;
    doc["reading_num"] = readingNumber;
    doc["timestamp"]   = getISO8601Timestamp();

    JsonObject s = doc.createNestedObject("sonar");
    if (distCm > 0) {
        s["distance_cm"] = round(distCm * 10.0f) / 10.0f;
        s["zone"]        = sonarZone(distCm);
        s["status"]      = "valid";
    } else {
        s["status"] = "error";
    }

    JsonObject o = doc.createNestedObject("object_1");
    o["detected"] = obj;
    o["raw"]      = obj ? 0 : 1;

    // Alert logic
    bool sonarAlert = (distCm > 0 && distCm < ZONE_NEAR_CM);

    if (sonarAlert && obj) {
        doc["alert"]       = "INTRUSION_CONFIRMED";
        doc["alert_level"] = "HIGH";
    } else if (sonarAlert) {
        doc["alert"]       = "INTRUSION_NEAR";
        doc["alert_level"] = "MEDIUM";
    } else if (obj) {
        doc["alert"]       = "OBJECT_DETECTED";
        doc["alert_level"] = "MEDIUM";
    } else {
        doc["alert"]       = "NONE";
        doc["alert_level"] = "NORMAL";
    }

    char buf[512];
    serializeJson(doc, buf);
    if (mqttClient.publish(TOPIC_COMBINED, buf)) messageCount++;
}

void publishHeartbeat() {
    StaticJsonDocument<384> doc;
    unsigned long uptime = (millis() - bootTime) / 1000;

    doc["node_id"]        = HC_NODE_ID;
    doc["type"]           = "heartbeat";
    doc["timestamp"]      = getISO8601Timestamp();
    doc["uptime_seconds"] = uptime;
    doc["wifi_rssi"]      = WiFi.RSSI();
    doc["wifi_ssid"]      = HC_SSID;
    doc["free_heap"]      = ESP.getFreeHeap();
    doc["ip_address"]     = WiFi.localIP().toString();
    doc["messages_sent"]  = messageCount;
    doc["readings_taken"] = readingNumber;
    doc["errors"]         = errorCount;
    doc["status"]         = "online";

    JsonObject last = doc.createNestedObject("last_readings");
    last["distance_cm"] = (lastDistCm > 0) ? lastDistCm : 0;
    last["object_1"]    = lastObj;

    char buf[384];
    serializeJson(doc, buf);
    if (mqttClient.publish(TOPIC_HEARTBEAT, buf)) {
        messageCount++;
        Serial.print("  HB | Up:");   Serial.print(uptime);
        Serial.print("s RSSI:");      Serial.print(WiFi.RSSI());
        Serial.print("dBm D:");
        if (lastDistCm > 0) { Serial.print(lastDistCm, 1); Serial.print("cm"); }
        else                { Serial.print("ERR"); }
        Serial.print(" Zone:"); Serial.println(sonarZone(lastDistCm));
    }
}

// ══════════════════════════════════════════════════════════════
//  SETUP
// ══════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    delay(1200);

    Serial.println();
    Serial.println("  ═══════════════════════════════════════════════════");
    Serial.println("  IWSN Security — ESP32 Sensor Node 2");
    Serial.println("  Sensors: SR04M-2 Sonar + Flying Fish OD");
    Serial.println("  ═══════════════════════════════════════════════════");
    Serial.println();
    Serial.print("  SSID: "); Serial.println(HC_SSID);
    Serial.print("  Node: "); Serial.println(HC_NODE_ID);
    Serial.println();

    // Pins
    pinMode(STATUS_LED,    OUTPUT);
    pinMode(SONAR_TRIG_PIN, OUTPUT);
    pinMode(SONAR_ECHO_PIN, INPUT);
    pinMode(OBJ_PIN,        INPUT_PULLUP);
    digitalWrite(SONAR_TRIG_PIN, LOW);

    // MQTT topics
    snprintf(TOPIC_SONAR,     sizeof(TOPIC_SONAR),     "iwsn/sensors/%s/sonar",     HC_NODE_ID);
    snprintf(TOPIC_OBJ,       sizeof(TOPIC_OBJ),       "iwsn/sensors/%s/object_1",  HC_NODE_ID);
    snprintf(TOPIC_COMBINED,  sizeof(TOPIC_COMBINED),  "iwsn/sensors/%s/combined",  HC_NODE_ID);
    snprintf(TOPIC_HEARTBEAT, sizeof(TOPIC_HEARTBEAT), "iwsn/sensors/%s/heartbeat", HC_NODE_ID);
    snprintf(TOPIC_ONLINE,    sizeof(TOPIC_ONLINE),    "iwsn/sensors/%s/online",    HC_NODE_ID);

    // WiFi + NTP + MQTT
    setupWiFi();
    setupNTP();
    mqttClient.setServer(HC_BROKER_IP, HC_BROKER_PORT);
    mqttClient.setBufferSize(512);
    Serial.print("  MQTT Broker: "); Serial.print(HC_BROKER_IP);
    Serial.print(":"); Serial.println(HC_BROKER_PORT);

    bootTime = millis();

    Serial.println();
    Serial.println("  Node 2 ready — publishing sensor data via MQTT");
    Serial.println("  ═══════════════════════════════════════════════════");
    Serial.println();
}

// ══════════════════════════════════════════════════════════════
//  MAIN LOOP
// ══════════════════════════════════════════════════════════════

void loop() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("  WiFi lost — reconnecting...");
        setupWiFi();
        setupNTP();
    }

    if (!mqttClient.connected()) reconnectMQTT();
    mqttClient.loop();

    unsigned long now = millis();

    // ── Read & publish sensors every SENSOR_INTERVAL_MS ──
    if (now - lastSensorRead >= SENSOR_INTERVAL_MS) {
        lastSensorRead = now;
        readingNumber++;

        Serial.print("  #"); Serial.print(readingNumber); Serial.print(" | ");

        // SR04M-2 sonar
        float distCm = sonarReadMedianCm();
        lastDistCm   = distCm;
        publishSonar(distCm);
        if (distCm > 0) {
            Serial.print("D:"); Serial.print(distCm, 1);
            Serial.print("cm ["); Serial.print(sonarZone(distCm)); Serial.print("] ");
        } else {
            Serial.print("SONAR:ERR ");
        }

        // Flying Fish OD
        bool obj = readObjectDetector();
        lastObj  = obj;
        publishObject(obj);
        Serial.print("OD:"); Serial.println(obj ? "OBJ" : "CLR");

        // Combined
        publishCombined(distCm, obj);
    }

    // ── Heartbeat ──
    if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeat = now;
        publishHeartbeat();
    }
}
