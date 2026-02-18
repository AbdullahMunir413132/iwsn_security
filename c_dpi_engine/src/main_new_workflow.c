/*
 * IWSN Security - New Workflow Implementation
 * 1. DPI Engine processes ALL packets first
 * 2. Rule Engine receives ALL flows and filters MQTT + checks anomalies
 * 3. MQTT Parser processes filtered MQTT flows and displays sensor values
 * 
 * WITH COMPREHENSIVE PERFORMANCE METRICS TRACKING!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/stat.h>
#include "dpi_engine.h"
#include "rule_engine.h"
#include "mqtt_parser.h"
#include "performance_metrics.h"
#include "detailed_reports.h"
#include "ids_reports.h"
#include "mqtt_reports.h"

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
    printf("║          WITH PERFORMANCE METRICS TRACKING                     ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // ===== INITIALIZE PERFORMANCE METRICS =====
    system_performance_t perf_metrics;
    perf_metrics_init(&perf_metrics);
    strncpy(perf_metrics.pcap_filename, pcap_file, sizeof(perf_metrics.pcap_filename) - 1);
    
    // Get PCAP file size
    struct stat st;
    if (stat(pcap_file, &st) == 0) {
        perf_metrics.pcap_file_size_bytes = st.st_size;
    }
    
    // ===== STEP 1: DPI ENGINE - Process ALL Packets =====
    printf("\n[STEP 1/3] Running DPI Engine on all packets...\n");
    printf("─────────────────────────────────────────────────────────────\n");
    
    perf_dpi_init(&perf_metrics.dpi_metrics);
    
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
    
    // Update DPI metrics
    perf_dpi_update(&perf_metrics.dpi_metrics, dpi_engine);
    perf_dpi_finalize(&perf_metrics.dpi_metrics);
    perf_metrics.pcap_duration_seconds = pcap_stats.duration_seconds;
    
    printf("\n✓ DPI Complete: %u packets, %u flows detected\n", 
           pcap_stats.total_packets, dpi_engine->flow_count);
    printf("  Processing time: %.2f ms (%lu packets/sec)\n",
           perf_metrics.dpi_metrics.processing_time_ms,
           perf_metrics.dpi_metrics.packets_per_second);
    
    // ===== STEP 2: RULE ENGINE - Filter MQTT + Check Anomalies =====
    printf("\n[STEP 2/3] Rule Engine: Filtering MQTT flows and checking anomalies...\n");
    printf("─────────────────────────────────────────────────────────────\n");
    
    perf_rule_engine_init(&perf_metrics.rule_engine_metrics);
    
    // Set ground truth: Determine if this is an attack PCAP based on filename
    perf_metrics.rule_engine_metrics.is_attack_pcap = perf_is_attack_pcap(pcap_file);
    if (perf_metrics.rule_engine_metrics.is_attack_pcap) {
        printf("📊 Ground Truth: ATTACK PCAP (will calculate accuracy metrics)\n");
    } else {
        printf("📊 Ground Truth: NORMAL TRAFFIC (will calculate accuracy metrics)\n");
    }
    
    rule_engine_t *rule_engine = rule_engine_init();
    if (!rule_engine) {
        fprintf(stderr, "Failed to initialize rule engine\n");
        dpi_engine_destroy(dpi_engine);
        return 1;
    }
    
    // Analyze ALL flows through rule engine (includes aggregate attack detection)
    rule_engine_analyze_all_flows(rule_engine, dpi_engine);
    
    // Now identify MQTT flows for later parsing
    uint32_t mqtt_flow_count = 0;
    uint32_t mqtt_flow_indices[10000];  // Store indices of MQTT flows
    
    printf("\n[Rule Engine] Identifying MQTT flows...\n");
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        flow_stats_t *flow = &dpi_engine->flows[i];
        
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
    
    // Update Rule Engine metrics
    perf_metrics.rule_engine_metrics.total_flows_analyzed = dpi_engine->flow_count;
    perf_rule_engine_update(&perf_metrics.rule_engine_metrics, rule_engine);
    perf_rule_engine_finalize(&perf_metrics.rule_engine_metrics, rule_engine);
    
    printf("\n✓ Rule Engine Complete: %u total flows, %u MQTT flows filtered\n",
           dpi_engine->flow_count, mqtt_flow_count);
    printf("✓ Attacks detected: %lu\n", rule_engine->total_attacks_detected);
    printf("  Processing time: %.2f ms (%.0f flows/sec)\n",
           perf_metrics.rule_engine_metrics.processing_time_ms,
           (double)perf_metrics.rule_engine_metrics.flows_per_second);
    
    // Print attack summary if any
    if (rule_engine->total_attacks_detected > 0) {
        print_attack_summary(rule_engine);
    }
    
    // ===== STEP 3: MQTT PARSER - Parse Filtered MQTT Flows =====
    printf("\n[STEP 3/3] MQTT Parser: Analyzing MQTT flows and extracting sensor data...\n");
    printf("─────────────────────────────────────────────────────────────\n");
    
    perf_mqtt_parser_init(&perf_metrics.mqtt_parser_metrics);
    
    uint32_t total_messages = 0;
    uint32_t successful_parses = 0;
    uint32_t sensor_data_count = 0;
    
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
                
                // Extract TCP payload - calculate offset properly
                if (pkt->layer4.protocol == 6 && pkt->raw_data_len > 0) {  // TCP
                    // Calculate proper offsets:
                    // Ethernet: 14 bytes (18 if VLAN)
                    // IP: from pkt->layer3.header_length
                    // TCP: extract from TCP header's data offset field
                    
                    uint32_t eth_offset = pkt->layer2.has_vlan ? 18 : 14;
                    uint32_t ip_header_len = pkt->layer3.header_length;
                    
                    // Get TCP header length from data offset field (bits 12-15 of byte 12)
                    uint32_t tcp_header_offset = eth_offset + ip_header_len;
                    if (tcp_header_offset + 13 >= pkt->raw_data_len) {
                        continue;  // Not enough data for TCP header
                    }
                    
                    const uint8_t *tcp_header = pkt->raw_data + tcp_header_offset;
                    uint32_t tcp_header_len = ((tcp_header[12] >> 4) & 0x0F) * 4;
                    
                    // Calculate application layer offset
                    uint32_t payload_offset = eth_offset + ip_header_len + tcp_header_len;
                    
                    if (payload_offset >= pkt->raw_data_len) {
                        continue;  // No application data (just TCP control packet)
                    }
                    
                    uint32_t payload_len = pkt->raw_data_len - payload_offset;
                    
                    if (payload_len > 0 && payload_len < 4096) {
                        mqtt_message_t msg;
                        memset(&msg, 0, sizeof(msg));
                        
                        total_messages++;
                        
                        if (parse_mqtt_packet(pkt->raw_data + payload_offset, payload_len, &msg)) {
                            mqtt_message_count++;
                            successful_parses++;
                            print_mqtt_message(&msg, pkt->packet_number);
                            
                            // Mark packet as MQTT and store info for report generation
                            pkt->is_mqtt = 1;
                            pkt->mqtt_packet_type = msg.message_type;
                            pkt->mqtt_payload_length = msg.payload_len;
                            
                            if (msg.message_type == MQTT_PUBLISH) {
                                strncpy(pkt->mqtt_topic, msg.topic, sizeof(pkt->mqtt_topic) - 1);
                                pkt->mqtt_topic[sizeof(pkt->mqtt_topic) - 1] = '\0';
                                if (msg.payload_len > 0) {
                                    size_t copy_len = (msg.payload_len < sizeof(pkt->mqtt_payload_data) - 1) ? 
                                                      msg.payload_len : sizeof(pkt->mqtt_payload_data) - 1;
                                    memcpy(pkt->mqtt_payload_data, msg.payload, copy_len);
                                    pkt->mqtt_payload_data[copy_len] = '\0';
                                }
                            } else if (msg.message_type == MQTT_CONNECT) {
                                // Store client ID for CONNECT messages
                                // msg doesn't have client_id directly, so we skip storing it for now
                            }
                            
                            // Try to extract sensor data
                            if (extract_sensor_data(&msg)) {
                                sensor_data_count++;
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
    
    // Update MQTT Parser metrics
    perf_mqtt_parser_update(&perf_metrics.mqtt_parser_metrics,
                           mqtt_flow_count, dpi_engine->flow_count,
                           total_messages, successful_parses,
                           sensor_data_count);
    perf_mqtt_parser_finalize(&perf_metrics.mqtt_parser_metrics);
    
    printf("\n✓ MQTT Parser Complete: %u flows, %u messages (%u successful)\n",
           mqtt_flow_count, total_messages, successful_parses);
    printf("  Processing time: %.2f ms\n",
           perf_metrics.mqtt_parser_metrics.processing_time_ms);
    
    // ===== FINALIZE SYSTEM METRICS =====
    perf_system_finalize(&perf_metrics);
    
    // ===== FINAL SUMMARY =====
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                    ANALYSIS COMPLETE                           ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Packets:    %-8u                                    ║\n", pcap_stats.total_packets);
    printf("║  Total Flows:      %-8u                                    ║\n", dpi_engine->flow_count);
    printf("║  MQTT Flows:       %-8u                                    ║\n", mqtt_flow_count);
    printf("║  Attacks Detected: %-8lu                                   ║\n", rule_engine->total_attacks_detected);
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    // ===== DISPLAY COMPREHENSIVE PERFORMANCE METRICS =====
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                              PERFORMANCE METRICS REPORT                                        ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
    
    // Print all metrics tables
    perf_print_all_metrics_table(&perf_metrics);
    
    // Save metrics to file
    perf_save_metrics_to_file(&perf_metrics, "performance_metrics.txt");
    printf("\n✓ Performance metrics saved to 'performance_metrics.txt'\n");
    
    // ===== GENERATE DETAILED REPORTS =====
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║              GENERATING DETAILED REPORTS                       ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    generate_dpi_detailed_report(dpi_engine, &pcap_stats, "dpi_detailed_report.txt");
    generate_ids_report(rule_engine, dpi_engine, "ids_detailed_report.txt");
    generate_mqtt_report(dpi_engine, "mqtt_packets_detailed.txt");
    
    // Cleanup
    rule_engine_destroy(rule_engine);
    dpi_engine_destroy(dpi_engine);
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                    ALL REPORTS GENERATED                       ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  performance_metrics.txt    - Performance summary              ║\n");
    printf("║  dpi_detailed_report.txt    - DPI flows & packets              ║\n");
    printf("║  ids_detailed_report.txt    - IDS/attack detection details     ║\n");
    printf("║  mqtt_packets_detailed.txt  - MQTT packets & payloads          ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    return 0;
}
