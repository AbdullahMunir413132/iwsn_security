/*
 * MQTT Report Generator
 * Generates detailed MQTT packet and payload reports
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "dpi_engine.h"

// Generate detailed MQTT packet report with payloads
void generate_mqtt_report(dpi_engine_t *engine, const char *output_file) {
    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", output_file);
        return;
    }
    
    fprintf(fp, "╔════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                              DETAILED MQTT PACKETS REPORT                                      ║\n");
    fprintf(fp, "╚════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
    
    // Count MQTT flows and packets
    uint32_t mqtt_flow_count = 0;
    uint32_t mqtt_packet_count = 0;
    
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        flow_stats_t *flow = &engine->flows[i];
        
        // Check if this is an MQTT flow
        int is_mqtt = 0;
        if (flow->src_port == 1883 || flow->dst_port == 1883) {
            is_mqtt = 1;
        } else if (strstr(flow->protocol_name, "MQTT") != NULL) {
            is_mqtt = 1;
        }
        
        if (is_mqtt) {
            mqtt_flow_count++;
            for (uint32_t p = 0; p < flow->packet_count_stored; p++) {
                parsed_packet_t *pkt = flow->packets[p];
                if (pkt->is_mqtt) {
                    mqtt_packet_count++;
                }
            }
        }
    }
    
    fprintf(fp, "Total MQTT Flows: %u\n", mqtt_flow_count);
    fprintf(fp, "Total MQTT Packets: %u\n\n", mqtt_packet_count);
    
    if (mqtt_flow_count == 0) {
        fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════\n");
        fprintf(fp, "                                  NO MQTT TRAFFIC DETECTED                                     \n");
        fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════\n\n");
        fprintf(fp, "This PCAP file does not contain any MQTT traffic.\n");
        fprintf(fp, "MQTT traffic typically uses TCP port 1883.\n\n");
        fprintf(fp, "To capture MQTT traffic:\n");
        fprintf(fp, "  1. Ensure MQTT broker is running on port 1883\n");
        fprintf(fp, "  2. Capture with filter: tcpdump -i any port 1883 -w mqtt_capture.pcap\n");
        fprintf(fp, "  3. Generate MQTT traffic using mosquitto_pub/sub or MQTT client\n\n");
    } else {
        fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════\n");
        fprintf(fp, "                                  MQTT PACKET DETAILS                                          \n");
        fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════\n\n");
        
        uint32_t mqtt_pkt_num = 0;
        
        // Iterate through all flows
        for (uint32_t f = 0; f < engine->flow_count; f++) {
            flow_stats_t *flow = &engine->flows[f];
            
            // Check if MQTT flow
            int is_mqtt = 0;
            if (flow->src_port == 1883 || flow->dst_port == 1883 || strstr(flow->protocol_name, "MQTT") != NULL) {
                is_mqtt = 1;
            }
            
            if (!is_mqtt) continue;
            
            fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
            fprintf(fp, " MQTT FLOW #%u - %s\n", f+1, flow->protocol_name);
            fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
            fprintf(fp, " %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u\n",
                   (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
                   (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF, flow->src_port,
                   (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
                   (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF, flow->dst_port);
            fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n\n");
            
            // Print all MQTT packets in this flow
            for (uint32_t p = 0; p < flow->packet_count_stored; p++) {
                parsed_packet_t *pkt = flow->packets[p];
                
                // Check if packet has TCP payload
                int has_tcp_payload = 0;
                if (pkt->layer4.protocol == 6 && pkt->raw_data_len > 0) {
                    uint32_t eth_offset = pkt->layer2.has_vlan ? 18 : 14;
                    uint32_t ip_header_len = pkt->layer3.header_length;
                    uint32_t tcp_header_offset = eth_offset + ip_header_len;
                    
                    if (tcp_header_offset + 13 < pkt->raw_data_len) {
                        const uint8_t *tcp_header = pkt->raw_data + tcp_header_offset;
                        uint32_t tcp_header_len = ((tcp_header[12] >> 4) & 0x0F) * 4;
                        uint32_t payload_offset = eth_offset + ip_header_len + tcp_header_len;
                        
                        if (payload_offset < pkt->raw_data_len) {
                            has_tcp_payload = 1;
                        }
                    }
                }
                
                if (!pkt->is_mqtt && has_tcp_payload) {
                    // For packets with TCP payload but not successfully parsed as MQTT
                    mqtt_pkt_num++;
                    
                    fprintf(fp, "┌─ MQTT Packet #%u (TCP Payload) ─────────────────────────────────────────────────────────\n", mqtt_pkt_num);
                    fprintf(fp, "│\n");
                    
                    char time_str[64];
                    struct tm *tm_info = localtime(&pkt->timestamp.tv_sec);
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                    fprintf(fp, "│  Timestamp:       %s.%06ld\n", time_str, pkt->timestamp.tv_usec);
                    fprintf(fp, "│  Packet Size:     %u bytes\n", pkt->layer3.packet_size);
                    fprintf(fp, "│  Direction:       %u.%u.%u.%u:%u → %u.%u.%u.%u:%u\n",
                           (pkt->layer3.src_ip >> 24) & 0xFF, (pkt->layer3.src_ip >> 16) & 0xFF,
                           (pkt->layer3.src_ip >> 8) & 0xFF, pkt->layer3.src_ip & 0xFF,
                           pkt->layer4.src_port,
                           (pkt->layer3.dst_ip >> 24) & 0xFF, (pkt->layer3.dst_ip >> 16) & 0xFF,
                           (pkt->layer3.dst_ip >> 8) & 0xFF, pkt->layer3.dst_ip & 0xFF,
                           pkt->layer4.dst_port);
                    
                    fprintf(fp, "│\n");
                    fprintf(fp, "│  MQTT Parse:      Not successfully parsed\n");
                    fprintf(fp, "│  Status:          TCP payload present but MQTT parsing failed\n");
                    fprintf(fp, "│  Note:            May be encrypted, fragmented, or non-MQTT data\n");
                    fprintf(fp, "│\n");
                    fprintf(fp, "└────────────────────────────────────────────────────────────────────────────────────────────\n\n");
                    continue;
                }
                
                if (pkt->is_mqtt) {
                    mqtt_pkt_num++;
                    
                    fprintf(fp, "┌─ MQTT Packet #%u ───────────────────────────────────────────────────────────────────────\n", mqtt_pkt_num);
                    fprintf(fp, "│\n");
                    
                    char time_str[64];
                    struct tm *tm_info = localtime(&pkt->timestamp.tv_sec);
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                    fprintf(fp, "│  Timestamp:       %s.%06ld\n", time_str, pkt->timestamp.tv_usec);
                    fprintf(fp, "│  Packet Size:     %u bytes\n", pkt->layer3.packet_size);
                    fprintf(fp, "│  Direction:       %u.%u.%u.%u:%u → %u.%u.%u.%u:%u\n",
                           (pkt->layer3.src_ip >> 24) & 0xFF, (pkt->layer3.src_ip >> 16) & 0xFF,
                           (pkt->layer3.src_ip >> 8) & 0xFF, pkt->layer3.src_ip & 0xFF,
                           pkt->layer4.src_port,
                           (pkt->layer3.dst_ip >> 24) & 0xFF, (pkt->layer3.dst_ip >> 16) & 0xFF,
                           (pkt->layer3.dst_ip >> 8) & 0xFF, pkt->layer3.dst_ip & 0xFF,
                           pkt->layer4.dst_port);
                    
                    fprintf(fp, "│\n");
                    fprintf(fp, "│  ┌─ MQTT Header ───────────────────────────────────────────────────────────\n");
                    fprintf(fp, "│  │\n");
                    fprintf(fp, "│  │  Packet Type:     ");
                    switch (pkt->mqtt_packet_type) {
                        case 1: fprintf(fp, "CONNECT\n"); break;
                        case 2: fprintf(fp, "CONNACK\n"); break;
                        case 3: fprintf(fp, "PUBLISH\n"); break;
                        case 4: fprintf(fp, "PUBACK\n"); break;
                        case 5: fprintf(fp, "PUBREC\n"); break;
                        case 6: fprintf(fp, "PUBREL\n"); break;
                        case 7: fprintf(fp, "PUBCOMP\n"); break;
                        case 8: fprintf(fp, "SUBSCRIBE\n"); break;
                        case 9: fprintf(fp, "SUBACK\n"); break;
                        case 10: fprintf(fp, "UNSUBSCRIBE\n"); break;
                        case 11: fprintf(fp, "UNSUBACK\n"); break;
                        case 12: fprintf(fp, "PINGREQ\n"); break;
                        case 13: fprintf(fp, "PINGRESP\n"); break;
                        case 14: fprintf(fp, "DISCONNECT\n"); break;
                        default: fprintf(fp, "Unknown (%u)\n", pkt->mqtt_packet_type); break;
                    }
                    
                    if (strlen(pkt->mqtt_client_id) > 0) {
                        fprintf(fp, "│  │  Client ID:       %s\n", pkt->mqtt_client_id);
                    }
                    
                    if (strlen(pkt->mqtt_topic) > 0) {
                        fprintf(fp, "│  │  Topic:           %s\n", pkt->mqtt_topic);
                    }
                    
                    fprintf(fp, "│  │  Payload Length:  %u bytes\n", pkt->mqtt_payload_length);
                    fprintf(fp, "│  │\n");
                    fprintf(fp, "│  └─────────────────────────────────────────────────────────────────────────\n");
                    
                    // Print payload if available
                    if (pkt->mqtt_payload_length > 0 && strlen(pkt->mqtt_payload_data) > 0) {
                        fprintf(fp, "│\n");
                        fprintf(fp, "│  ┌─ MQTT Payload ──────────────────────────────────────────────────────────\n");
                        fprintf(fp, "│  │\n");
                        
                        // Print payload as text (up to 512 bytes)
                        const char *payload = pkt->mqtt_payload_data;
                        uint32_t len = strlen(payload) < pkt->mqtt_payload_length ? strlen(payload) : pkt->mqtt_payload_length;
                        
                        if (len > 512) {
                            fprintf(fp, "│  │  \"%.*s...\"\n", 512, payload);
                            fprintf(fp, "│  │  (%u more bytes not shown)\n", len - 512);
                        } else {
                            fprintf(fp, "│  │  \"%s\"\n", payload);
                        }
                        
                        fprintf(fp, "│  │\n");
                        fprintf(fp, "│  └─────────────────────────────────────────────────────────────────────────\n");
                    }
                    
                    fprintf(fp, "│\n");
                    fprintf(fp, "└────────────────────────────────────────────────────────────────────────────────────────────\n\n");
                }
            }
        }
    }
    
    fprintf(fp, "\n╔════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                                END OF MQTT REPORT                                              ║\n");
    fprintf(fp, "╚════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
    
    fclose(fp);
    printf("✓ MQTT packet report saved to: %s\n", output_file);
}
