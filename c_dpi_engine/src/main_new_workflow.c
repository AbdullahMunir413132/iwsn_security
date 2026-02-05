/*
 * IWSN Security - New Workflow Implementation
 * 1. DPI Engine processes ALL packets first
 * 2. Rule Engine receives ALL flows and filters MQTT + checks anomalies
 * 3. MQTT Parser processes filtered MQTT flows and displays sensor values
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/stat.h>
#include "dpi_engine.h"
#include "rule_engine.h"
#include "mqtt_parser.h"

/* ========== Main Program ========== */

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        fprintf(stderr, "Example: %s /tmp/capture.pcap\n", argv[0]);
        return 1;
    }
    
    const char *pcap_file = argv[1];
    
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║         IWSN SECURITY - DPI + MQTT ANALYSIS v3.0               ║\n");
    printf("║    DPI → Rule Engine (MQTT Filter) → MQTT Parser              ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // ===== STEP 1: DPI ENGINE - Process ALL Packets =====
    printf("\n[STEP 1/3] Running DPI Engine on all packets...\n");
    printf("─────────────────────────────────────────────────────────────\n");
    
    dpi_engine_t *dpi_engine = dpi_engine_init(10000);
    if (!dpi_engine) {
        fprintf(stderr, "Failed to initialize DPI engine\n");
        return 1;
    }
    
    // Process PCAP file through DPI
    pcap_stats_t pcap_stats;
    if (process_pcap_file(pcap_file, dpi_engine, &pcap_stats) != 0) {
        fprintf(stderr, "Failed to process PCAP file\n");
        dpi_engine_destroy(dpi_engine);
        return 1;
    }
    
    printf("\n✓ DPI Complete: %u packets, %u flows detected\n", 
           pcap_stats.total_packets, dpi_engine->flow_count);
    
    // ===== STEP 2: RULE ENGINE - Filter MQTT + Check Anomalies =====
    printf("\n[STEP 2/3] Rule Engine: Filtering MQTT flows and checking anomalies...\n");
    printf("─────────────────────────────────────────────────────────────\n");
    
    rule_engine_t *rule_engine = rule_engine_init();
    if (!rule_engine) {
        fprintf(stderr, "Failed to initialize rule engine\n");
        dpi_engine_destroy(dpi_engine);
        return 1;
    }
    
    // Analyze all flows through rule engine
    uint32_t mqtt_flow_count = 0;
    uint32_t mqtt_flow_indices[10000];  // Store indices of MQTT flows
    
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        flow_stats_t *flow = &dpi_engine->flows[i];
        
        // Send flow to rule engine
        rule_engine_analyze_flow(rule_engine, flow);
        
        // Check if this is an MQTT flow (port 1883 or detected as MQTT)
        int is_mqtt = 0;
        if (flow->src_port == 1883 || flow->dst_port == 1883) {
            is_mqtt = 1;
        } else if (strstr(flow->protocol_name, "MQTT") != NULL) {
            is_mqtt = 1;
        }
        
        if (is_mqtt) {
            mqtt_flow_indices[mqtt_flow_count++] = i;
            printf("  ✓ MQTT Flow #%u detected: %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u\n",
                   mqtt_flow_count,
                   (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
                   (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF,
                   flow->src_port,
                   (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
                   (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF,
                   flow->dst_port);
        }
    }
    
    printf("\n✓ Rule Engine Complete: %u total flows, %u MQTT flows filtered\n",
           dpi_engine->flow_count, mqtt_flow_count);
    printf("✓ Attacks detected: %lu\n", rule_engine->total_attacks_detected);
    
    // Print attack summary if any
    if (rule_engine->total_attacks_detected > 0) {
        print_attack_summary(rule_engine);
    }
    
    // ===== STEP 3: MQTT PARSER - Parse Filtered MQTT Flows =====
    printf("\n[STEP 3/3] MQTT Parser: Analyzing MQTT flows and extracting sensor data...\n");
    printf("─────────────────────────────────────────────────────────────\n");
    
    if (mqtt_flow_count == 0) {
        printf("\n⚠ No MQTT flows found in capture.\n");
        printf("   Hint: Capture traffic on port 1883 or ensure MQTT protocol is present.\n");
    } else {
        printf("\nAnalyzing %u MQTT flows...\n\n", mqtt_flow_count);
        
        for (uint32_t i = 0; i < mqtt_flow_count; i++) {
            flow_stats_t *flow = &dpi_engine->flows[mqtt_flow_indices[i]];
            
            printf("═══════════════════════════════════════════════════════════════\n");
            printf(" MQTT FLOW #%u ANALYSIS\n", i + 1);
            printf("═══════════════════════════════════════════════════════════════\n");
            printf("  5-Tuple: %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u\n",
                   (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
                   (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF,
                   flow->src_port,
                   (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
                   (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF,
                   flow->dst_port);
            printf("  Total Packets: %lu\n", flow->total_packets);
            printf("  Protocol: %s\n\n", flow->protocol_name);
            
            // Parse all packets in this MQTT flow
            uint32_t mqtt_message_count = 0;
            for (uint32_t p = 0; p < flow->packet_count_stored; p++) {
                parsed_packet_t *pkt = flow->packets[p];
                
                // Extract TCP payload - calculate offset and length
                if (pkt->layer4.protocol == 6 && pkt->raw_data_len > 54) {  // TCP
                    // Skip Ethernet(14) + IP(20) + TCP(20) = 54 bytes minimum
                    uint32_t payload_offset = 54;  // Simplified - may need adjustment
                    uint32_t payload_len = pkt->raw_data_len - payload_offset;
                    
                    if (payload_len > 0 && payload_len < 2000) {
                        mqtt_message_t msg;
                        memset(&msg, 0, sizeof(msg));
                        
                        if (parse_mqtt_packet(pkt->raw_data + payload_offset, payload_len, &msg)) {
                            mqtt_message_count++;
                            print_mqtt_message(&msg, pkt->packet_number);
                            
                            // Try to extract sensor data
                            if (extract_sensor_data(&msg)) {
                                printf("\n    📊 SENSOR DATA DETECTED:\n");
                                printf("       Type:  %s\n", msg.sensor_type);
                                printf("       Value: %.2f %s\n", msg.sensor_value, msg.sensor_unit);
                                printf("\n");
                            }
                        }
                    }
                }
            }
            
            if (mqtt_message_count == 0) {
                printf("  ⚠ No valid MQTT messages parsed in this flow\n");
                printf("    (Flow may be incomplete or encrypted)\n");
            } else {
                printf("\n  ✓ Total MQTT messages parsed: %u\n", mqtt_message_count);
            }
            printf("\n");
        }
    }
    
    // ===== FINAL SUMMARY =====
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                    ANALYSIS COMPLETE                           ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Packets:    %-8u                                    ║\n", pcap_stats.total_packets);
    printf("║  Total Flows:      %-8u                                    ║\n", dpi_engine->flow_count);
    printf("║  MQTT Flows:       %-8u                                    ║\n", mqtt_flow_count);
    printf("║  Attacks Detected: %-8lu                                   ║\n", rule_engine->total_attacks_detected);
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    // Cleanup
    rule_engine_destroy(rule_engine);
    dpi_engine_destroy(dpi_engine);
    
    return 0;
}
