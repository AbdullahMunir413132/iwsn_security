/*
 * ══════════════════════════════════════════════════════════════════════════
 *  IWSN SECURITY — ESP32 Sensor Node 1
 * ══════════════════════════════════════════════════════════════════════════
 *
 *  Hardware Components:
 *    - 1x DHT11 Temperature & Humidity Sensor
 *    - 1x Flying Fish IR Obstacle Detector
 *    - ESP-WROOM-32D
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  WIRING DIAGRAM
 * ──────────────────────────────────────────────────────────────────────────
 *
 *  DHT11 Sensor:
 *    VCC → 3.3V
 *    GND → GND
 *    DATA → GPIO4
 *
 *  Flying Fish IR:
 *    VCC → 3.3V
 *    GND → GND
 *    OUT → GPIO14 (LOW = object detected)
 *
 *  Built-in LED:
 *    GPIO2
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  MQTT Topics:
 *    iwsn/sensors/esp32_node_01/dht11
 *    iwsn/sensors/esp32_node_01/object_1
 *    iwsn/sensors/esp32_node_01/combined
 *    iwsn/sensors/esp32_node_01/heartbeat
 *    iwsn/sensors/esp32_node_01/online
 * ══════════════════════════════════════════════════════════════════════════
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>
#include <time.h>

// ─────────────────────────────────────────
// Credentials
// ─────────────────────────────────────────
#define HC_SSID        "OnePlus 8"
#define HC_PASS        "69000069"
#define HC_BROKER_IP   "10.136.166.1"
#define HC_BROKER_PORT 1883
#define HC_NODE_ID     "esp32_node_01"

// ─────────────────────────────────────────
// Pins
// ─────────────────────────────────────────
#define DHT_PIN     4
#define DHT_TYPE    DHT11

#define OBJ_PIN     14
#define OBJ_ACTIVE  LOW

#define STATUS_LED  2

// ─────────────────────────────────────────
// Timing
// ─────────────────────────────────────────
#define SENSOR_INTERVAL_MS    2000
#define HEARTBEAT_INTERVAL_MS 10000

// ─────────────────────────────────────────
// Objects
// ─────────────────────────────────────────
WiFiClient espClient;
PubSubClient mqttClient(espClient);
DHT dht(DHT_PIN, DHT_TYPE);

// Topics
char TOPIC_DHT[64];
char TOPIC_OBJ[64];
char TOPIC_COMBINED[64];
char TOPIC_HEARTBEAT[64];
char TOPIC_ONLINE[64];

// State
unsigned long lastSensorRead = 0;
unsigned long lastHeartbeat  = 0;
unsigned long bootTime       = 0;

uint32_t readingNumber = 0;
uint32_t messageCount  = 0;

float lastTemp = 0;
float lastHum  = 0;
bool  lastObj  = false;

// ─────────────────────────────────────────
// Timestamp
// ─────────────────────────────────────────
String getTimestamp() {
    return String(millis());
}

// ─────────────────────────────────────────
// WiFi
// ─────────────────────────────────────────
void setupWiFi() {
    WiFi.begin(HC_SSID, HC_PASS);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
    }
    digitalWrite(STATUS_LED, HIGH);
}

// ─────────────────────────────────────────
// MQTT reconnect
// ─────────────────────────────────────────
void reconnectMQTT() {
    while (!mqttClient.connected()) {
        String clientId = String(HC_NODE_ID) + "_" + String(random(0xffff), HEX);

        if (mqttClient.connect(clientId.c_str())) {
            StaticJsonDocument<200> doc;
            doc["node_id"] = HC_NODE_ID;
            doc["event"]   = "online";

            char buf[200];
            serializeJson(doc, buf);
            mqttClient.publish(TOPIC_ONLINE, buf, true);
        } else {
            delay(2000);
        }
    }
}

// ─────────────────────────────────────────
// Sensor Reads
// ─────────────────────────────────────────
bool readObject() {
    return digitalRead(OBJ_PIN) == OBJ_ACTIVE;
}

// ─────────────────────────────────────────
// Publishing
// ─────────────────────────────────────────
void publishDHT(float temp, float hum) {
    StaticJsonDocument<256> doc;

    doc["sensor_id"]   = "DHT11";
    doc["temperature"] = temp;
    doc["humidity"]    = hum;
    doc["reading_num"] = readingNumber;
    doc["timestamp"]   = getTimestamp();

    char buf[256];
    serializeJson(doc, buf);
    mqttClient.publish(TOPIC_DHT, buf);
}

void publishObject(bool obj) {
    StaticJsonDocument<200> doc;

    doc["sensor_id"] = "FF_OD_1";
    doc["detected"]  = obj;
    doc["reading_num"] = readingNumber;
    doc["timestamp"] = getTimestamp();

    char buf[200];
    serializeJson(doc, buf);
    mqttClient.publish(TOPIC_OBJ, buf);
}

void publishCombined(float temp, float hum, bool obj) {
    StaticJsonDocument<300> doc;

    doc["node_id"] = HC_NODE_ID;
    doc["reading_num"] = readingNumber;

    JsonObject dht = doc.createNestedObject("dht11");
    dht["temp"] = temp;
    dht["hum"]  = hum;

    JsonObject o = doc.createNestedObject("object_1");
    o["detected"] = obj;

    if (obj) {
        doc["alert"] = "OBJECT_DETECTED";
    } else {
        doc["alert"] = "NORMAL";
    }

    char buf[300];
    serializeJson(doc, buf);
    mqttClient.publish(TOPIC_COMBINED, buf);
}

void publishHeartbeat() {
    StaticJsonDocument<300> doc;

    doc["node_id"] = HC_NODE_ID;
    doc["uptime"]  = (millis() - bootTime) / 1000;
    doc["messages"] = messageCount;

    char buf[300];
    serializeJson(doc, buf);
    mqttClient.publish(TOPIC_HEARTBEAT, buf);
}

// ─────────────────────────────────────────
// Setup
// ─────────────────────────────────────────
void setup() {
    Serial.begin(115200);

    pinMode(STATUS_LED, OUTPUT);
    pinMode(OBJ_PIN, INPUT_PULLUP);

    dht.begin();

    snprintf(TOPIC_DHT, 64, "iwsn/sensors/%s/dht11", HC_NODE_ID);
    snprintf(TOPIC_OBJ, 64, "iwsn/sensors/%s/object_1", HC_NODE_ID);
    snprintf(TOPIC_COMBINED, 64, "iwsn/sensors/%s/combined", HC_NODE_ID);
    snprintf(TOPIC_HEARTBEAT, 64, "iwsn/sensors/%s/heartbeat", HC_NODE_ID);
    snprintf(TOPIC_ONLINE, 64, "iwsn/sensors/%s/online", HC_NODE_ID);

    setupWiFi();

    mqttClient.setServer(HC_BROKER_IP, HC_BROKER_PORT);

    bootTime = millis();
}

// ─────────────────────────────────────────
// Loop
// ─────────────────────────────────────────
void loop() {
    if (!mqttClient.connected()) reconnectMQTT();
    mqttClient.loop();

    unsigned long now = millis();

    if (now - lastSensorRead >= SENSOR_INTERVAL_MS) {
        lastSensorRead = now;
        readingNumber++;

        float temp = dht.readTemperature();
        float hum  = dht.readHumidity();
        bool obj   = readObject();

        lastTemp = temp;
        lastHum  = hum;
        lastObj  = obj;

        publishDHT(temp, hum);
        publishObject(obj);
        publishCombined(temp, hum, obj);

        Serial.print("Temp: "); Serial.print(temp);
        Serial.print(" Hum: "); Serial.print(hum);
        Serial.print(" Obj: "); Serial.println(obj ? "YES" : "NO");
    }

    if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeat = now;
        publishHeartbeat();
    }
}