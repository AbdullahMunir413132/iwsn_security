/*
 * MQTT Parser Header
 * Decodes MQTT packets from raw payload data
 */

#ifndef MQTT_PARSER_H
#define MQTT_PARSER_H

#include <stdint.h>
#include <sys/time.h>

/* ========== MQTT Packet Types ========== */
#define MQTT_CONNECT      1
#define MQTT_CONNACK      2
#define MQTT_PUBLISH      3
#define MQTT_PUBACK       4
#define MQTT_PUBREC       5
#define MQTT_PUBREL       6
#define MQTT_PUBCOMP      7
#define MQTT_SUBSCRIBE    8
#define MQTT_SUBACK       9
#define MQTT_UNSUBSCRIBE  10
#define MQTT_UNSUBACK     11
#define MQTT_PINGREQ      12
#define MQTT_PINGRESP     13
#define MQTT_DISCONNECT   14

/* ========== MQTT Parser Structures ========== */

typedef struct {
    uint8_t packet_type;
    uint8_t qos;
    uint8_t retain;
    uint8_t dup;
    uint32_t remaining_length;
    uint16_t packet_id;
    
    // CONNECT specific
    char protocol_name[32];
    uint8_t protocol_version;
    uint8_t connect_flags;
    uint16_t keep_alive;
    char client_id[256];
    char username[256];
    char password[256];
    char will_topic[256];
    char will_message[512];
    
    // PUBLISH specific
    char topic[256];
    uint8_t *payload;
    uint32_t payload_length;
    
    // SUBSCRIBE specific
    char subscribe_topics[10][256];
    uint8_t subscribe_qos[10];
    uint8_t subscribe_count;
    
    // Parsing status
    uint8_t is_valid;
    char error_message[256];
    
} mqtt_packet_t;

typedef struct {
    uint64_t total_packets;
    uint64_t connect_count;
    uint64_t connack_count;
    uint64_t publish_count;
    uint64_t subscribe_count;
    uint64_t unsubscribe_count;
    uint64_t pingreq_count;
    uint64_t pingresp_count;
    uint64_t disconnect_count;
    uint64_t invalid_count;
    
    // Anomaly detection
    uint64_t malformed_packets;
    uint64_t oversized_packets;
    uint64_t suspicious_topics;
    
} mqtt_statistics_t;

/* ========== Simplified MQTT Message Structure (for workflow) ========== */

typedef struct {
    uint8_t message_type;
    uint8_t qos;
    uint8_t retain;
    uint8_t dup;
    uint16_t packet_id;
    
    char topic[256];
    uint8_t payload[1024];
    uint16_t payload_len;
    
    // Parsed sensor data (if applicable)
    int has_sensor_data;
    char sensor_type[64];
    double sensor_value;
    char sensor_unit[32];
} mqtt_message_t;

/* MQTT Flow Statistics */
typedef struct {
    uint32_t publish_count;
    uint32_t subscribe_count;
    uint32_t connect_count;
    uint32_t total_messages;
    
    char topics[10][256];
    uint32_t topic_count;
} mqtt_flow_stats_t;

/* ========== Function Prototypes ========== */

// Initialize MQTT parser
int mqtt_parser_init(void);

// Parse MQTT packet from raw payload
int mqtt_parse_packet(const uint8_t *data, uint32_t data_len, mqtt_packet_t *packet);

// Get packet type name
const char* mqtt_get_packet_type_name(uint8_t packet_type);

// Validate MQTT packet for anomalies
int mqtt_detect_anomalies(const mqtt_packet_t *packet, char *anomaly_desc, size_t desc_len);

// Check if port/protocol indicates MQTT
int is_mqtt_traffic(uint16_t src_port, uint16_t dst_port, const uint8_t *payload, uint32_t payload_len);

// Print MQTT packet details
void mqtt_print_packet(const mqtt_packet_t *packet);

// Get MQTT statistics
void mqtt_get_statistics(mqtt_statistics_t *stats);

// Reset MQTT statistics
void mqtt_reset_statistics(void);

// Cleanup MQTT parser
void mqtt_parser_cleanup(void);

/* ========== Wrapper Functions for New Workflow ========== */
// Note: These require dpi_engine.h to be included first for flow_stats_t

// Parse MQTT packet (wrapper)
int parse_mqtt_packet(const uint8_t *data, uint32_t len, mqtt_message_t *msg);

// Extract sensor data from MQTT payload
int extract_sensor_data(mqtt_message_t *msg);

// Print MQTT message details
void print_mqtt_message(const mqtt_message_t *msg, uint32_t packet_num);

// Print MQTT flow summary (forward declare if needed)
#ifdef DPI_ENGINE_H
void print_mqtt_flow_summary(const flow_stats_t *flow, const mqtt_flow_stats_t *mqtt_stats);
#endif

#endif /* MQTT_PARSER_H */
