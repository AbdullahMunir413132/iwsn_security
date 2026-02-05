/*
 * MQTT Parser Implementation
 * Decodes MQTT v3.1 and v3.1.1 packets from raw payload data
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "mqtt_parser.h"

/* ========== Global Statistics ========== */
static mqtt_statistics_t global_mqtt_stats = {0};

/* ========== Helper Functions ========== */

// Decode remaining length (variable length encoding)
static int decode_remaining_length(const uint8_t *data, uint32_t data_len, uint32_t *remaining_len, uint32_t *bytes_consumed) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    uint32_t pos = 0;
    uint8_t encoded_byte;
    
    do {
        if (pos >= data_len || pos >= 4) {
            return -1; // Invalid encoding
        }
        
        encoded_byte = data[pos];
        value += (encoded_byte & 127) * multiplier;
        multiplier *= 128;
        pos++;
        
        if (multiplier > 128*128*128) {
            return -1; // Malformed
        }
    } while ((encoded_byte & 128) != 0);
    
    *remaining_len = value;
    *bytes_consumed = pos;
    return 0;
}

// Read UTF-8 string from MQTT packet
static int read_mqtt_string(const uint8_t *data, uint32_t data_len, uint32_t *pos, char *output, size_t output_len) {
    if (*pos + 2 > data_len) {
        return -1;
    }
    
    uint16_t str_len = (data[*pos] << 8) | data[*pos + 1];
    *pos += 2;
    
    if (*pos + str_len > data_len || str_len >= output_len) {
        return -1;
    }
    
    memcpy(output, &data[*pos], str_len);
    output[str_len] = '\0';
    *pos += str_len;
    
    return 0;
}

/* ========== Packet Type Parsers ========== */

static int parse_connect_packet(const uint8_t *payload, uint32_t payload_len, mqtt_packet_t *packet) {
    uint32_t pos = 0;
    
    // Read protocol name
    if (read_mqtt_string(payload, payload_len, &pos, packet->protocol_name, sizeof(packet->protocol_name)) < 0) {
        strcpy(packet->error_message, "Failed to read protocol name");
        return -1;
    }
    
    // Read protocol version
    if (pos >= payload_len) return -1;
    packet->protocol_version = payload[pos++];
    
    // Read connect flags
    if (pos >= payload_len) return -1;
    packet->connect_flags = payload[pos++];
    
    // Read keep alive
    if (pos + 2 > payload_len) return -1;
    packet->keep_alive = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;
    
    // Read client ID
    if (read_mqtt_string(payload, payload_len, &pos, packet->client_id, sizeof(packet->client_id)) < 0) {
        strcpy(packet->error_message, "Failed to read client ID");
        return -1;
    }
    
    // Will topic and message (if present)
    if (packet->connect_flags & 0x04) { // Will flag
        if (read_mqtt_string(payload, payload_len, &pos, packet->will_topic, sizeof(packet->will_topic)) < 0) {
            strcpy(packet->error_message, "Failed to read will topic");
            return -1;
        }
        if (read_mqtt_string(payload, payload_len, &pos, packet->will_message, sizeof(packet->will_message)) < 0) {
            strcpy(packet->error_message, "Failed to read will message");
            return -1;
        }
    }
    
    // Username (if present)
    if (packet->connect_flags & 0x80) {
        if (read_mqtt_string(payload, payload_len, &pos, packet->username, sizeof(packet->username)) < 0) {
            strcpy(packet->error_message, "Failed to read username");
            return -1;
        }
    }
    
    // Password (if present)
    if (packet->connect_flags & 0x40) {
        if (read_mqtt_string(payload, payload_len, &pos, packet->password, sizeof(packet->password)) < 0) {
            strcpy(packet->error_message, "Failed to read password");
            return -1;
        }
    }
    
    global_mqtt_stats.connect_count++;
    return 0;
}

static int parse_publish_packet(const uint8_t *payload, uint32_t payload_len, mqtt_packet_t *packet) {
    uint32_t pos = 0;
    
    // Read topic name
    if (read_mqtt_string(payload, payload_len, &pos, packet->topic, sizeof(packet->topic)) < 0) {
        strcpy(packet->error_message, "Failed to read topic");
        return -1;
    }
    
    // Read packet ID (if QoS > 0)
    if (packet->qos > 0) {
        if (pos + 2 > payload_len) return -1;
        packet->packet_id = (payload[pos] << 8) | payload[pos + 1];
        pos += 2;
    }
    
    // Read payload
    packet->payload_length = payload_len - pos;
    if (packet->payload_length > 0) {
        packet->payload = (uint8_t*)malloc(packet->payload_length + 1);
        if (packet->payload) {
            memcpy(packet->payload, &payload[pos], packet->payload_length);
            packet->payload[packet->payload_length] = '\0'; // Null terminate for safety
        }
    }
    
    global_mqtt_stats.publish_count++;
    return 0;
}

static int parse_subscribe_packet(const uint8_t *payload, uint32_t payload_len, mqtt_packet_t *packet) {
    uint32_t pos = 0;
    
    // Read packet ID
    if (pos + 2 > payload_len) return -1;
    packet->packet_id = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;
    
    // Read topic filters
    packet->subscribe_count = 0;
    while (pos < payload_len && packet->subscribe_count < 10) {
        if (read_mqtt_string(payload, payload_len, &pos, 
                            packet->subscribe_topics[packet->subscribe_count], 
                            sizeof(packet->subscribe_topics[0])) < 0) {
            break;
        }
        
        // Read QoS
        if (pos >= payload_len) break;
        packet->subscribe_qos[packet->subscribe_count] = payload[pos++];
        packet->subscribe_count++;
    }
    
    global_mqtt_stats.subscribe_count++;
    return 0;
}

/* ========== Public API ========== */

int mqtt_parser_init(void) {
    memset(&global_mqtt_stats, 0, sizeof(mqtt_statistics_t));
    return 0;
}

int mqtt_parse_packet(const uint8_t *data, uint32_t data_len, mqtt_packet_t *packet) {
    if (!data || data_len < 2 || !packet) {
        return -1;
    }
    
    memset(packet, 0, sizeof(mqtt_packet_t));
    packet->is_valid = 0;
    
    // Parse fixed header
    uint8_t fixed_header = data[0];
    packet->packet_type = (fixed_header >> 4) & 0x0F;
    packet->dup = (fixed_header >> 3) & 0x01;
    packet->qos = (fixed_header >> 1) & 0x03;
    packet->retain = fixed_header & 0x01;
    
    // Decode remaining length
    uint32_t bytes_consumed = 0;
    if (decode_remaining_length(&data[1], data_len - 1, &packet->remaining_length, &bytes_consumed) < 0) {
        strcpy(packet->error_message, "Invalid remaining length encoding");
        global_mqtt_stats.malformed_packets++;
        return -1;
    }
    
    uint32_t header_len = 1 + bytes_consumed;
    if (header_len + packet->remaining_length > data_len) {
        strcpy(packet->error_message, "Packet length exceeds available data");
        global_mqtt_stats.malformed_packets++;
        return -1;
    }
    
    const uint8_t *payload = &data[header_len];
    uint32_t payload_len = packet->remaining_length;
    
    // Parse variable header and payload based on packet type
    int parse_result = 0;
    switch (packet->packet_type) {
        case MQTT_CONNECT:
            parse_result = parse_connect_packet(payload, payload_len, packet);
            break;
            
        case MQTT_PUBLISH:
            parse_result = parse_publish_packet(payload, payload_len, packet);
            break;
            
        case MQTT_SUBSCRIBE:
            parse_result = parse_subscribe_packet(payload, payload_len, packet);
            break;
            
        case MQTT_CONNACK:
            global_mqtt_stats.connack_count++;
            break;
            
        case MQTT_PINGREQ:
            global_mqtt_stats.pingreq_count++;
            break;
            
        case MQTT_PINGRESP:
            global_mqtt_stats.pingresp_count++;
            break;
            
        case MQTT_DISCONNECT:
            global_mqtt_stats.disconnect_count++;
            break;
            
        case MQTT_UNSUBSCRIBE:
            global_mqtt_stats.unsubscribe_count++;
            break;
            
        default:
            snprintf(packet->error_message, sizeof(packet->error_message), 
                    "Unknown packet type: %d", packet->packet_type);
            global_mqtt_stats.invalid_count++;
            return -1;
    }
    
    if (parse_result < 0) {
        global_mqtt_stats.malformed_packets++;
        return -1;
    }
    
    packet->is_valid = 1;
    global_mqtt_stats.total_packets++;
    return 0;
}

const char* mqtt_get_packet_type_name(uint8_t packet_type) {
    switch (packet_type) {
        case MQTT_CONNECT:      return "CONNECT";
        case MQTT_CONNACK:      return "CONNACK";
        case MQTT_PUBLISH:      return "PUBLISH";
        case MQTT_PUBACK:       return "PUBACK";
        case MQTT_PUBREC:       return "PUBREC";
        case MQTT_PUBREL:       return "PUBREL";
        case MQTT_PUBCOMP:      return "PUBCOMP";
        case MQTT_SUBSCRIBE:    return "SUBSCRIBE";
        case MQTT_SUBACK:       return "SUBACK";
        case MQTT_UNSUBSCRIBE:  return "UNSUBSCRIBE";
        case MQTT_UNSUBACK:     return "UNSUBACK";
        case MQTT_PINGREQ:      return "PINGREQ";
        case MQTT_PINGRESP:     return "PINGRESP";
        case MQTT_DISCONNECT:   return "DISCONNECT";
        default:                return "UNKNOWN";
    }
}

int mqtt_detect_anomalies(const mqtt_packet_t *packet, char *anomaly_desc, size_t desc_len) {
    if (!packet || !packet->is_valid) {
        return 0;
    }
    
    // Check for suspicious topics
    if (packet->packet_type == MQTT_PUBLISH || packet->packet_type == MQTT_SUBSCRIBE) {
        const char *topic = (packet->packet_type == MQTT_PUBLISH) ? packet->topic : 
                           (packet->subscribe_count > 0 ? packet->subscribe_topics[0] : "");
        
        // Check for command injection patterns
        if (strstr(topic, "$(") || strstr(topic, "`") || strstr(topic, "../") || 
            strstr(topic, "..\\") || strstr(topic, "<script>")) {
            snprintf(anomaly_desc, desc_len, "Suspicious topic contains injection patterns: %s", topic);
            global_mqtt_stats.suspicious_topics++;
            return 1;
        }
        
        // Check for excessively long topics
        if (strlen(topic) > 200) {
            snprintf(anomaly_desc, desc_len, "Topic name too long: %zu bytes", strlen(topic));
            global_mqtt_stats.suspicious_topics++;
            return 1;
        }
    }
    
    // Check for oversized payloads
    if (packet->packet_type == MQTT_PUBLISH && packet->payload_length > 1024*1024) {
        snprintf(anomaly_desc, desc_len, "PUBLISH payload too large: %u bytes", packet->payload_length);
        global_mqtt_stats.oversized_packets++;
        return 1;
    }
    
    // Check for suspicious client IDs
    if (packet->packet_type == MQTT_CONNECT) {
        if (strlen(packet->client_id) > 200 || strlen(packet->client_id) == 0) {
            snprintf(anomaly_desc, desc_len, "Suspicious client ID length: %zu", strlen(packet->client_id));
            return 1;
        }
    }
    
    return 0;
}

int is_mqtt_traffic(uint16_t src_port, uint16_t dst_port, const uint8_t *payload, uint32_t payload_len) {
    // Check standard MQTT ports
    if (src_port == 1883 || dst_port == 1883 ||  // MQTT
        src_port == 8883 || dst_port == 8883) {  // MQTT over TLS
        return 1;
    }
    
    // Try to detect MQTT by packet structure
    if (payload && payload_len >= 2) {
        uint8_t packet_type = (payload[0] >> 4) & 0x0F;
        if (packet_type >= 1 && packet_type <= 14) {
            // Could be MQTT, do additional validation
            uint32_t remaining_len, bytes_consumed;
            if (decode_remaining_length(&payload[1], payload_len - 1, &remaining_len, &bytes_consumed) == 0) {
                // If it looks like valid MQTT encoding, probably is MQTT
                if (remaining_len > 0 && remaining_len < 256*1024) { // Reasonable size
                    return 1;
                }
            }
        }
    }
    
    return 0;
}

void mqtt_print_packet(const mqtt_packet_t *packet) {
    if (!packet || !packet->is_valid) {
        printf("  [MQTT] Invalid or malformed packet\n");
        return;
    }
    
    printf("  [MQTT] Type: %s", mqtt_get_packet_type_name(packet->packet_type));
    
    if (packet->qos > 0) {
        printf(" | QoS: %d", packet->qos);
    }
    if (packet->retain) {
        printf(" | RETAIN");
    }
    if (packet->dup) {
        printf(" | DUP");
    }
    printf("\n");
    
    switch (packet->packet_type) {
        case MQTT_CONNECT:
            printf("  [MQTT] Protocol: %s v%d\n", packet->protocol_name, packet->protocol_version);
            printf("  [MQTT] Client ID: %s\n", packet->client_id);
            printf("  [MQTT] Keep Alive: %d seconds\n", packet->keep_alive);
            if (strlen(packet->username) > 0) {
                printf("  [MQTT] Username: %s\n", packet->username);
            }
            break;
            
        case MQTT_PUBLISH:
            printf("  [MQTT] Topic: %s\n", packet->topic);
            printf("  [MQTT] Payload Length: %u bytes\n", packet->payload_length);
            if (packet->payload && packet->payload_length > 0 && packet->payload_length < 200) {
                // Try to print as text if reasonable size
                int is_printable = 1;
                for (uint32_t i = 0; i < packet->payload_length && i < 100; i++) {
                    if (packet->payload[i] < 32 && packet->payload[i] != '\n' && packet->payload[i] != '\r' && packet->payload[i] != '\t') {
                        is_printable = 0;
                        break;
                    }
                }
                if (is_printable) {
                    printf("  [MQTT] Payload: %.*s\n", (int)packet->payload_length, packet->payload);
                }
            }
            break;
            
        case MQTT_SUBSCRIBE:
            printf("  [MQTT] Packet ID: %d\n", packet->packet_id);
            printf("  [MQTT] Topics:\n");
            for (int i = 0; i < packet->subscribe_count; i++) {
                printf("    - %s (QoS %d)\n", packet->subscribe_topics[i], packet->subscribe_qos[i]);
            }
            break;
    }
}

void mqtt_get_statistics(mqtt_statistics_t *stats) {
    if (stats) {
        memcpy(stats, &global_mqtt_stats, sizeof(mqtt_statistics_t));
    }
}

void mqtt_reset_statistics(void) {
    memset(&global_mqtt_stats, 0, sizeof(mqtt_statistics_t));
}

void mqtt_parser_cleanup(void) {
    // Nothing to cleanup currently
}
