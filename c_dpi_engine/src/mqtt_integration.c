/*
 * MQTT Integration Implementation
 * Parses MQTT packets AFTER attack detection for secure processing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "mqtt_integration.h"
#include "mqtt_parser.h"
#include "dpi_engine.h"

/* ========== Parse MQTT Packet (Post-Attack Detection) ========== */

int parse_mqtt_packet_secure(parsed_packet_t *parsed) {
    if (!parsed) {
        return -1;
    }
    
    // Check if this is MQTT traffic (port-based)
    if (parsed->layer4.dst_port != 1883 && parsed->layer4.src_port != 1883 &&
        parsed->layer4.dst_port != 8883 && parsed->layer4.src_port != 8883) {
        return 0;  // Not MQTT
    }
    
    // Extract TCP payload (skip headers)
    uint32_t eth_len = 14;
    if (parsed->layer2.has_vlan) eth_len = 18;
    uint32_t ip_len = parsed->layer3.header_length;
    uint32_t tcp_len = 0;
    
    // Calculate TCP header length (data offset * 4)
    if (parsed->layer4.protocol == IPPROTO_TCP && parsed->raw_data_len > eth_len + ip_len) {
        const uint8_t *tcp_header = parsed->raw_data + eth_len + ip_len;
        tcp_len = ((tcp_header[12] >> 4) & 0x0F) * 4;
    }
    
    uint32_t app_offset = eth_len + ip_len + tcp_len;
    if (app_offset >= parsed->raw_data_len) {
        return -1;  // No application data
    }
    
    const uint8_t *app_data = parsed->raw_data + app_offset;
    uint32_t app_len = parsed->raw_data_len - app_offset;
    
    // Parse MQTT packet
    mqtt_packet_t mqtt_pkt;
    if (mqtt_parse_packet(app_data, app_len, &mqtt_pkt) < 0) {
        return -1;  // Not valid MQTT or parsing failed
    }
    
    // Store MQTT information in parsed structure
    parsed->is_mqtt = 1;
    parsed->mqtt_packet_type = mqtt_pkt.packet_type;
    parsed->mqtt_payload_length = mqtt_pkt.payload_length;
    
    // Store type-specific data
    if (mqtt_pkt.packet_type == MQTT_CONNECT) {
        strncpy(parsed->mqtt_client_id, mqtt_pkt.client_id, sizeof(parsed->mqtt_client_id) - 1);
        parsed->mqtt_client_id[sizeof(parsed->mqtt_client_id) - 1] = '\0';
    } else if (mqtt_pkt.packet_type == MQTT_PUBLISH) {
        strncpy(parsed->mqtt_topic, mqtt_pkt.topic, sizeof(parsed->mqtt_topic) - 1);
        parsed->mqtt_topic[sizeof(parsed->mqtt_topic) - 1] = '\0';
        
        // Store payload data (sensor values)
        if (mqtt_pkt.payload && mqtt_pkt.payload_length > 0) {
            size_t copy_len = (mqtt_pkt.payload_length < sizeof(parsed->mqtt_payload_data) - 1) ?
                              mqtt_pkt.payload_length : sizeof(parsed->mqtt_payload_data) - 1;
            memcpy(parsed->mqtt_payload_data, mqtt_pkt.payload, copy_len);
            parsed->mqtt_payload_data[copy_len] = '\0';
        }
    }
    
    // Update protocol name
    strcpy(parsed->detected_protocol, "MQTT");
    if (parsed->flow) {
        snprintf(parsed->flow->protocol_name, sizeof(parsed->flow->protocol_name), 
                "MQTT.%s", mqtt_get_packet_type_name(mqtt_pkt.packet_type));
    }
    
    // Check for MQTT-specific security anomalies
    char anomaly_desc[256];
    if (mqtt_detect_anomalies(&mqtt_pkt, anomaly_desc, sizeof(anomaly_desc))) {
        printf("[MQTT SECURITY ALERT] %s\n", anomaly_desc);
        printf("  Source: %u.%u.%u.%u:%u\n",
               (parsed->layer3.src_ip >> 24) & 0xFF,
               (parsed->layer3.src_ip >> 16) & 0xFF,
               (parsed->layer3.src_ip >> 8) & 0xFF,
               parsed->layer3.src_ip & 0xFF,
               parsed->layer4.src_port);
    }
    
    // Cleanup
    if (mqtt_pkt.payload) {
        free(mqtt_pkt.payload);
    }
    
    return 0;
}

/* ========== Print MQTT Statistics ========== */

void print_mqtt_statistics(void) {
    mqtt_statistics_t stats;
    mqtt_get_statistics(&stats);
    
    if (stats.total_packets == 0) {
        return;  // No MQTT traffic
    }
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║                   MQTT PROTOCOL STATISTICS                     ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("[MQTT PACKET BREAKDOWN]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total MQTT Packets:    %lu\n", stats.total_packets);
    printf("  CONNECT:               %lu\n", stats.connect_count);
    printf("  CONNACK:               %lu\n", stats.connack_count);
    printf("  PUBLISH:               %lu\n", stats.publish_count);
    printf("  SUBSCRIBE:             %lu\n", stats.subscribe_count);
    printf("  UNSUBSCRIBE:           %lu\n", stats.unsubscribe_count);
    printf("  PINGREQ:               %lu\n", stats.pingreq_count);
    printf("  PINGRESP:              %lu\n", stats.pingresp_count);
    printf("  DISCONNECT:            %lu\n", stats.disconnect_count);
    
    if (stats.invalid_count > 0 || stats.malformed_packets > 0 || 
        stats.oversized_packets > 0 || stats.suspicious_topics > 0) {
        printf("\n[MQTT SECURITY ANOMALIES]\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("  Invalid Packets:       %lu\n", stats.invalid_count);
        printf("  Malformed Packets:     %lu\n", stats.malformed_packets);
        printf("  Oversized Packets:     %lu\n", stats.oversized_packets);
        printf("  Suspicious Topics:     %lu\n", stats.suspicious_topics);
    }
    
    printf("\n");
}
