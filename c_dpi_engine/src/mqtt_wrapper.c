/*
 * MQTT Wrapper Functions
 * Bridge between new workflow and existing MQTT parser
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "mqtt_parser.h"
#include "dpi_engine.h"

/* Map mqtt_packet_t to mqtt_message_t for compatibility */
int parse_mqtt_packet(const uint8_t *data, uint32_t len, mqtt_message_t *msg) {
    mqtt_packet_t packet;
    memset(&packet, 0, sizeof(packet));
    
    if (mqtt_parse_packet(data, len, &packet) != 0 || !packet.is_valid) {
        return 0;
    }
    
    // Map fields
    msg->message_type = packet.packet_type;
    msg->qos = packet.qos;
    msg->retain = packet.retain;
    msg->dup = packet.dup;
    msg->packet_id = packet.packet_id;
    
    if (packet.packet_type == MQTT_PUBLISH) {
        size_t topic_len = sizeof(msg->topic);
        strncpy(msg->topic, packet.topic, topic_len - 1);
        msg->topic[topic_len - 1] = '\0';
        if (packet.payload && packet.payload_length > 0) {
            msg->payload_len = (packet.payload_length < sizeof(msg->payload)) ? 
                               packet.payload_length : sizeof(msg->payload) - 1;
            memcpy(msg->payload, packet.payload, msg->payload_len);
        }
    }
    
    msg->has_sensor_data = 0;
    
    return 1;
}

/* Extract sensor data from MQTT payload */
int extract_sensor_data(mqtt_message_t *msg) {
    if (msg->message_type != MQTT_PUBLISH || msg->payload_len == 0) {
        return 0;
    }
    
    // Make payload null-terminated for string operations
    char payload_str[1024];
    uint16_t copy_len = (msg->payload_len < sizeof(payload_str) - 1) ? 
                        msg->payload_len : sizeof(payload_str) - 1;
    memcpy(payload_str, msg->payload, copy_len);
    payload_str[copy_len] = '\0';
    
    // Check if payload is printable text
    int is_text = 1;
    for (int i = 0; i < copy_len; i++) {
        if (!isprint(payload_str[i]) && payload_str[i] != '\n' && 
            payload_str[i] != '\r' && payload_str[i] != '\t') {
            is_text = 0;
            break;
        }
    }
    
    if (!is_text) {
        return 0;
    }
    
    // Try to parse common sensor data formats
    // Format 1: "temperature:25.5"
    if (sscanf(payload_str, "%63[^:]:%lf", msg->sensor_type, &msg->sensor_value) == 2) {
        strcpy(msg->sensor_unit, "°C");
        msg->has_sensor_data = 1;
        return 1;
    }
    
    // Format 2: "temperature 25.5 C"
    char unit_temp[32];
    if (sscanf(payload_str, "%63s %lf %31s", msg->sensor_type, &msg->sensor_value, unit_temp) == 3) {
        size_t unit_len = sizeof(msg->sensor_unit);
        strncpy(msg->sensor_unit, unit_temp, unit_len - 1);
        msg->sensor_unit[unit_len - 1] = '\0';
        msg->has_sensor_data = 1;
        return 1;
    }
    
    // Format 3: JSON-like {"temp":25.5}
    if (strstr(payload_str, "temp") || strstr(payload_str, "temperature")) {
        double value;
        if (sscanf(payload_str, "%*[^0-9-]%lf", &value) == 1) {
            strcpy(msg->sensor_type, "temperature");
            msg->sensor_value = value;
            strcpy(msg->sensor_unit, "°C");
            msg->has_sensor_data = 1;
            return 1;
        }
    }
    
    // Format 4: Just a number (assume temperature)
    double value;
    if (sscanf(payload_str, "%lf", &value) == 1) {
        strcpy(msg->sensor_type, "sensor_value");
        msg->sensor_value = value;
        strcpy(msg->sensor_unit, "");
        msg->has_sensor_data = 1;
        return 1;
    }
    
    return 0;
}

/* Print MQTT message details */
void print_mqtt_message(const mqtt_message_t *msg, uint32_t packet_num) {
    const char *type_name;
    switch (msg->message_type) {
        case MQTT_CONNECT:      type_name = "CONNECT"; break;
        case MQTT_CONNACK:      type_name = "CONNACK"; break;
        case MQTT_PUBLISH:      type_name = "PUBLISH"; break;
        case MQTT_PUBACK:       type_name = "PUBACK"; break;
        case MQTT_SUBSCRIBE:    type_name = "SUBSCRIBE"; break;
        case MQTT_SUBACK:       type_name = "SUBACK"; break;
        case MQTT_PINGREQ:      type_name = "PINGREQ"; break;
        case MQTT_PINGRESP:     type_name = "PINGRESP"; break;
        case MQTT_DISCONNECT:   type_name = "DISCONNECT"; break;
        default:                type_name = "UNKNOWN"; break;
    }
    
    printf("\n  ┌─ MQTT Message (Packet #%u) ─────────────────────────\n", packet_num);
    printf("  │ Type: %s", type_name);
    if (msg->qos > 0) printf(" | QoS: %d", msg->qos);
    if (msg->retain) printf(" | RETAIN");
    if (msg->dup) printf(" | DUP");
    printf("\n");
    
    if (msg->message_type == MQTT_PUBLISH) {
        printf("  │ Topic: %s\n", msg->topic);
        printf("  │ Payload Length: %u bytes\n", msg->payload_len);
        
        // Try to display payload as text
        if (msg->payload_len > 0 && msg->payload_len < 200) {
            int is_printable = 1;
            for (int i = 0; i < msg->payload_len; i++) {
                if (!isprint(msg->payload[i]) && msg->payload[i] != '\n' && 
                    msg->payload[i] != '\r' && msg->payload[i] != '\t') {
                    is_printable = 0;
                    break;
                }
            }
            
            if (is_printable) {
                printf("  │ Payload: %.*s\n", (int)msg->payload_len, msg->payload);
            } else {
                printf("  │ Payload: [binary data]\n");
            }
        }
    }
    
    printf("  └────────────────────────────────────────────────────\n");
}

/* Print MQTT flow summary */
void print_mqtt_flow_summary(const flow_stats_t *flow, const mqtt_flow_stats_t *mqtt_stats) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf(" MQTT FLOW SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Flow: %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u\n",
           (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
           (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF, flow->src_port,
           (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
           (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF, flow->dst_port);
    
    printf("\n  MQTT Statistics:\n");
    printf("    Total Messages:  %u\n", mqtt_stats->total_messages);
    printf("    PUBLISH:         %u\n", mqtt_stats->publish_count);
    printf("    SUBSCRIBE:       %u\n", mqtt_stats->subscribe_count);
    printf("    CONNECT:         %u\n", mqtt_stats->connect_count);
    
    if (mqtt_stats->topic_count > 0) {
        printf("\n  Topics:\n");
        for (uint32_t i = 0; i < mqtt_stats->topic_count && i < 10; i++) {
            printf("    - %s\n", mqtt_stats->topics[i]);
        }
    }
    printf("\n");
}
