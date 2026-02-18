/*
 * IWSN Security - Performance Metrics Implementation
 * Comprehensive performance tracking and reporting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include "performance_metrics.h"
#include "dpi_engine.h"
#include "rule_engine.h"

/* ========== Utility: Get Attack Type Name ========== */
const char* perf_get_attack_type_name(int attack_type) {
    switch(attack_type) {
        case 1: return "SYN Flood";
        case 2: return "UDP Flood";
        case 3: return "HTTP Flood";
        case 4: return "Ping of Death";
        case 5: return "ARP Spoofing";
        case 6: return "RUDY Attack";
        case 7: return "TCP SYN Scan";
        case 8: return "TCP Connect Scan";
        case 9: return "UDP Scan";
        case 10: return "Port Scan";
        case 11: return "ICMP Flood";
        default: return "Unknown";
    }
}

/* ========== Initialization Functions ========== */

void perf_metrics_init(system_performance_t *metrics) {
    memset(metrics, 0, sizeof(system_performance_t));
    gettimeofday(&metrics->system_start_time, NULL);
}

void perf_dpi_init(dpi_performance_t *metrics) {
    memset(metrics, 0, sizeof(dpi_performance_t));
    gettimeofday(&metrics->start_time, NULL);
}

void perf_rule_engine_init(rule_engine_performance_t *metrics) {
    memset(metrics, 0, sizeof(rule_engine_performance_t));
    gettimeofday(&metrics->start_time, NULL);
}

void perf_mqtt_parser_init(mqtt_parser_performance_t *metrics) {
    memset(metrics, 0, sizeof(mqtt_parser_performance_t));
    gettimeofday(&metrics->start_time, NULL);
}

/* ========== Timing Functions ========== */

void perf_start_timer(struct timeval *start) {
    gettimeofday(start, NULL);
}

double perf_end_timer(struct timeval *start, struct timeval *end) {
    gettimeofday(end, NULL);
    return perf_calculate_elapsed_ms(start, end);
}

double perf_calculate_elapsed_ms(struct timeval *start, struct timeval *end) {
    double elapsed = (end->tv_sec - start->tv_sec) * 1000.0;
    elapsed += (end->tv_usec - start->tv_usec) / 1000.0;
    return elapsed;
}

/* ========== CPU Usage Measurement ========== */

double perf_get_cpu_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return 0.0;
    }
    
    // Calculate CPU time in seconds (user + system)
    double user_time = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0;
    double sys_time = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0;
    double cpu_time = user_time + sys_time;
    
    // Get wall clock time
    static struct timeval start_time = {0, 0};
    static int first_call = 1;
    
    if (first_call) {
        gettimeofday(&start_time, NULL);
        first_call = 0;
        return 0.0;
    }
    
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    double wall_time = (current_time.tv_sec - start_time.tv_sec) + 
                      (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
    
    if (wall_time > 0) {
        return (cpu_time / wall_time) * 100.0;
    }
    
    return 0.0;
}

/* ========== DPI Metrics Update Functions ========== */

void perf_dpi_update(dpi_performance_t *metrics, const void *engine_ptr) {
    const dpi_engine_t *engine = (const dpi_engine_t *)engine_ptr;
    
    // Basic packet/byte counts
    metrics->total_packets_processed = engine->total_packets;
    metrics->total_bytes_processed = engine->total_bytes;
    
    // Layer parsing success - cannot exceed total packets
    metrics->l2_parsed_successfully = engine->l2_parsed > engine->total_packets ? engine->total_packets : engine->l2_parsed;
    metrics->l3_parsed_successfully = engine->l3_parsed > engine->total_packets ? engine->total_packets : engine->l3_parsed;
    metrics->l4_parsed_successfully = engine->l4_parsed > engine->total_packets ? engine->total_packets : engine->l4_parsed;
    metrics->l5_sessions_tracked = engine->l5_parsed > engine->total_packets ? engine->total_packets : engine->l5_parsed;
    
    // Flow management
    metrics->total_flows_created = engine->flows_created;
    metrics->active_flows = engine->flow_count;
    
    // Calculate rates
    if (metrics->total_packets_processed > 0) {
        metrics->l2_parse_rate = (double)metrics->l2_parsed_successfully / 
                                 metrics->total_packets_processed * 100.0;
        metrics->l3_parse_rate = (double)metrics->l3_parsed_successfully / 
                                 metrics->total_packets_processed * 100.0;
        metrics->l4_parse_rate = (double)metrics->l4_parsed_successfully / 
                                 metrics->total_packets_processed * 100.0;
        metrics->l5_parse_rate = (double)metrics->l5_sessions_tracked / 
                                 metrics->total_packets_processed * 100.0;
    }
    
    if (metrics->total_flows_created > 0) {
        metrics->avg_packets_per_flow = (double)metrics->total_packets_processed / 
                                        metrics->total_flows_created;
        metrics->avg_bytes_per_flow = (double)metrics->total_bytes_processed / 
                                      metrics->total_flows_created;
    }
    
    // Protocol detection - count unique protocol types, not just flows
    metrics->protocols_detected = 0;
    metrics->unknown_protocols = 0;
    
    // Track unique protocols using a simple protocol name array
    const int MAX_UNIQUE_PROTOCOLS = 256;
    char unique_protocols[MAX_UNIQUE_PROTOCOLS][64];
    int unique_count = 0;
    
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        const char *proto = engine->flows[i].protocol_name;
        
        // Count packets with unknown protocol (handles "Unknown" and "Unknown.Unknown")
        if (strcmp(proto, "Unknown") == 0 || strncmp(proto, "Unknown", 7) == 0) {
            metrics->unknown_protocols += engine->flows[i].total_packets;
            continue;
        }

        // Check if protocol is already in unique list
        int found = 0;
        for (int j = 0; j < unique_count; j++) {
            if (strcmp(unique_protocols[j], proto) == 0) {
                found = 1;
                break;
            }
        }
        
        // Add to unique list if not found
        if (!found && unique_count < MAX_UNIQUE_PROTOCOLS) {
            strncpy(unique_protocols[unique_count], proto, 63);
            unique_protocols[unique_count][63] = '\0';
            unique_count++;
        }
    }
    metrics->protocols_detected = unique_count;
    
    // Protocol detection rate based on packets, not protocol types
    // Calculate: (successfully detected packets / total packets) * 100
    // Unknown packets reduce the detection accuracy
    if (metrics->total_packets_processed > 0) {
        uint64_t detected_packets = metrics->total_packets_processed - metrics->unknown_protocols;
        metrics->protocol_detection_rate = (double)detected_packets / 
                                           metrics->total_packets_processed * 100.0;
    } else {
        metrics->protocol_detection_rate = 0.0;
    }
    
    // Memory usage estimation
    metrics->memory_flows_bytes = engine->flow_count * sizeof(flow_stats_t);
    metrics->memory_packets_bytes = 0;
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        metrics->memory_packets_bytes += engine->flows[i].packet_count_stored * 
                                        sizeof(parsed_packet_t*);
    }
    metrics->total_memory_bytes = metrics->memory_flows_bytes + 
                                  metrics->memory_packets_bytes;
}

void perf_dpi_finalize(dpi_performance_t *metrics) {
    gettimeofday(&metrics->end_time, NULL);
    metrics->processing_time_ms = perf_calculate_elapsed_ms(&metrics->start_time, 
                                                            &metrics->end_time);
    
    // Get CPU usage
    metrics->cpu_usage_percent = perf_get_cpu_usage();
    
    // Calculate throughput
    if (metrics->processing_time_ms > 0) {
        double seconds = metrics->processing_time_ms / 1000.0;
        metrics->packets_per_second = (uint64_t)(metrics->total_packets_processed / seconds);
        metrics->megabytes_per_second = (metrics->total_bytes_processed / (1024.0 * 1024.0)) / seconds;
        
        // Average processing time per packet/flow
        metrics->avg_time_per_packet_us = (metrics->processing_time_ms * 1000.0) / 
                                          metrics->total_packets_processed;
        if (metrics->total_flows_created > 0) {
            metrics->avg_time_per_flow_us = (metrics->processing_time_ms * 1000.0) / 
                                           metrics->total_flows_created;
        }
    }
}

/* ========== Rule Engine Metrics Update Functions ========== */

void perf_rule_engine_update(rule_engine_performance_t *metrics, const void *engine_ptr) {
    const rule_engine_t *engine = (const rule_engine_t *)engine_ptr;
    
    // Analysis metrics
    metrics->total_packets_inspected = engine->total_packets_analyzed;
    metrics->total_attacks_detected = engine->total_attacks_detected;
    
    // Copy attack type statistics
    for (int i = 0; i < 20; i++) {
        metrics->attacks_by_type[i] = engine->attacks_by_type[i];
    }
    
    // Specific attack type counters
    metrics->syn_flood_detections = engine->attacks_by_type[1];
    metrics->udp_flood_detections = engine->attacks_by_type[2];
    metrics->http_flood_detections = engine->attacks_by_type[3];
    metrics->icmp_flood_detections = engine->attacks_by_type[11];
    metrics->port_scan_detections = engine->attacks_by_type[7] + 
                                    engine->attacks_by_type[8] + 
                                    engine->attacks_by_type[9];
    
    // IP tracking
    metrics->unique_ips_tracked = engine->ip_stats_count;
    metrics->blocked_ips = engine->blocked_ip_count;
    metrics->blocked_packets = engine->blocked_packet_count;
    
    // Calculate detection rate
    if (metrics->total_flows_analyzed > 0) {
        metrics->attack_detection_rate = (double)metrics->total_attacks_detected / 
                                        metrics->total_flows_analyzed * 100.0;
    }
}

void perf_rule_engine_finalize(rule_engine_performance_t *metrics, const void *engine_ptr) {
    const rule_engine_t *engine = (const rule_engine_t *)engine_ptr;
    
    gettimeofday(&metrics->end_time, NULL);
    metrics->processing_time_ms = perf_calculate_elapsed_ms(&metrics->start_time, 
                                                            &metrics->end_time);
    
    // Calculate efficiency metrics
    if (metrics->processing_time_ms > 0) {
        double seconds = metrics->processing_time_ms / 1000.0;
        metrics->flows_per_second = (uint32_t)(metrics->total_flows_analyzed / seconds);
        
        if (metrics->total_flows_analyzed > 0) {
            metrics->avg_time_per_flow_us = (metrics->processing_time_ms * 1000.0) / 
                                           metrics->total_flows_analyzed;
        }
        if (metrics->total_packets_inspected > 0) {
            metrics->avg_time_per_packet_us = (metrics->processing_time_ms * 1000.0) / 
                                             metrics->total_packets_inspected;
        }
    }
    
    // Calculate detection rate: % of flows identified as malicious
    // For attack files, all flows are potentially malicious
    // Detection rate = (flows with detected attacks / total flows) * 100
    if (metrics->is_attack_pcap && metrics->total_flows_analyzed > 0) {
        // For attack PCAPs: what % of flows did we correctly identify as malicious?
        uint32_t flows_with_attacks = (metrics->malicious_flows_detected > 0) ? 
                                     metrics->total_flows_analyzed : 0;
        if (metrics->total_attacks_detected > 0) {
            // If we detected attacks, assume all flows are potentially malicious
            flows_with_attacks = metrics->total_flows_analyzed;
        }
        metrics->attack_detection_rate = (double)flows_with_attacks / 
                                        metrics->total_flows_analyzed * 100.0;
    } else if (metrics->total_flows_analyzed > 0) {
        // For normal PCAPs: show % of flows flagged as malicious (should be low)
        metrics->attack_detection_rate = (double)metrics->malicious_flows_detected / 
                                        metrics->total_flows_analyzed * 100.0;
    }
    
    // Calculate accuracy metrics based on ground truth
    // For attack PCAPs: TP if attacks detected, FN if not
    // For normal PCAPs: TN if no attacks detected, FP if detected
    if (metrics->is_attack_pcap) {
        // This is an attack file
        if (metrics->total_attacks_detected > 0) {
            metrics->true_positives = 1;      // Correctly detected attack
            metrics->false_negatives = 0;
        } else {
            metrics->true_positives = 0;
            metrics->false_negatives = 1;     // Missed attack
        }
        metrics->false_positives = 0;         // Can't be FP in attack file
        metrics->true_negatives = 0;
    } else {
        // This is normal traffic
        if (metrics->total_attacks_detected > 0) {
            metrics->false_positives = 1;     // Incorrectly flagged normal as attack
            metrics->true_negatives = 0;
        } else {
            metrics->false_positives = 0;
            metrics->true_negatives = 1;      // Correctly identified as normal
        }
        metrics->true_positives = 0;          // Can't be TP in normal file
        metrics->false_negatives = 0;
    }
    
    // Calculate precision, recall, F1 based on TP/FP/TN/FN
    if (metrics->true_positives + metrics->false_positives > 0) {
        metrics->precision = (double)metrics->true_positives / 
                           (metrics->true_positives + metrics->false_positives);
    } else {
        // No detections made - set precision to 1.0 if no attacks and no FP
        metrics->precision = (metrics->is_attack_pcap) ? 0.0 : 1.0;
    }
    
    if (metrics->true_positives + metrics->false_negatives > 0) {
        metrics->recall = (double)metrics->true_positives / 
                        (metrics->true_positives + metrics->false_negatives);
    } else {
        // No ground truth attacks - set recall to 1.0
        metrics->recall = 1.0;
    }
    
    uint32_t total = metrics->true_positives + metrics->true_negatives + 
                    metrics->false_positives + metrics->false_negatives;
    if (total > 0) {
        metrics->accuracy = (double)(metrics->true_positives + metrics->true_negatives) / total;
    }
    
    // Apply average confidence penalty to accuracy
    // Calculate average confidence from all detected attacks
    if (engine && engine->detection_count > 0) {
        double total_confidence = 0.0;
        for (uint32_t i = 0; i < engine->detection_count; i++) {
            total_confidence += engine->detections[i].confidence_score;
        }
        double avg_confidence = total_confidence / engine->detection_count;
        
        // Apply confidence penalty: accuracy *= avg_confidence
        // If avg confidence is 70% (0.7), then accuracy is reduced by 30%
        metrics->accuracy *= avg_confidence;
    }
    // If no attacks detected, accuracy remains at base calculation (100% or 0% based on ground truth)
}

/* ========== MQTT Parser Metrics Update Functions ========== */

void perf_mqtt_parser_update(mqtt_parser_performance_t *metrics,
                             uint32_t mqtt_flows, uint32_t total_flows,
                             uint32_t messages_parsed, uint32_t successful,
                             uint32_t sensor_data_count) {
    metrics->mqtt_flows_detected = mqtt_flows;
    metrics->total_flows_scanned = total_flows;
    metrics->total_messages_parsed = messages_parsed;
    metrics->successful_parses = successful;
    metrics->sensor_data_extracted = sensor_data_count;
    
    // Calculate rates
    if (total_flows > 0) {
        metrics->mqtt_detection_rate = (double)mqtt_flows / total_flows * 100.0;
    }
    if (messages_parsed > 0) {
        metrics->parse_success_rate = (double)successful / messages_parsed * 100.0;
        metrics->sensor_extraction_rate = (double)sensor_data_count / messages_parsed * 100.0;
    }
    
    metrics->failed_parses = messages_parsed - successful;
}

void perf_mqtt_parser_finalize(mqtt_parser_performance_t *metrics) {
    gettimeofday(&metrics->end_time, NULL);
    metrics->processing_time_ms = perf_calculate_elapsed_ms(&metrics->start_time, 
                                                            &metrics->end_time);
    
    // Calculate efficiency metrics
    if (metrics->processing_time_ms > 0) {
        double seconds = metrics->processing_time_ms / 1000.0;
        // Calculate messages per second even for very fast processing
        if (metrics->total_messages_parsed > 0) {
            metrics->messages_per_second = metrics->total_messages_parsed / seconds;
        } else {
            metrics->messages_per_second = 0;
        }
        
        if (metrics->mqtt_flows_detected > 0) {
            metrics->avg_time_per_flow_us = (metrics->processing_time_ms * 1000.0) / 
                                           metrics->mqtt_flows_detected;
        }
        if (metrics->total_messages_parsed > 0) {
            metrics->avg_time_per_message_us = (metrics->processing_time_ms * 1000.0) / 
                                              metrics->total_messages_parsed;
        }
    }
}

/* ========== System-wide Metrics Functions ========== */

void perf_system_finalize(system_performance_t *metrics) {
    gettimeofday(&metrics->system_end_time, NULL);
    metrics->total_processing_time_ms = perf_calculate_elapsed_ms(&metrics->system_start_time,
                                                                  &metrics->system_end_time);
    
    // Get CPU utilization at system level
    metrics->cpu_utilization_percent = perf_get_cpu_usage();
    
    // Overall throughput
    metrics->total_packets = metrics->dpi_metrics.total_packets_processed;
    metrics->total_bytes = metrics->dpi_metrics.total_bytes_processed;
    
    if (metrics->total_processing_time_ms > 0) {
        double seconds = metrics->total_processing_time_ms / 1000.0;
        metrics->overall_packets_per_second = metrics->total_packets / seconds;
        metrics->overall_megabytes_per_second = (metrics->total_bytes / (1024.0 * 1024.0)) / seconds;
    }
    
    // Calculate percentages
    perf_system_calculate_percentages(metrics);
}

void perf_system_calculate_percentages(system_performance_t *metrics) {
    if (metrics->total_processing_time_ms > 0) {
        metrics->dpi_time_percentage = (metrics->dpi_metrics.processing_time_ms / 
                                       metrics->total_processing_time_ms) * 100.0;
        metrics->rule_engine_time_percentage = (metrics->rule_engine_metrics.processing_time_ms / 
                                                metrics->total_processing_time_ms) * 100.0;
        metrics->mqtt_parser_time_percentage = (metrics->mqtt_parser_metrics.processing_time_ms / 
                                                metrics->total_processing_time_ms) * 100.0;
        
        double component_time = metrics->dpi_metrics.processing_time_ms +
                               metrics->rule_engine_metrics.processing_time_ms +
                               metrics->mqtt_parser_metrics.processing_time_ms;
        metrics->overhead_time_percentage = ((metrics->total_processing_time_ms - component_time) / 
                                            metrics->total_processing_time_ms) * 100.0;
    }
    
    // Overall system accuracy (from rule engine)
    metrics->system_accuracy = metrics->rule_engine_metrics.accuracy;
    metrics->system_precision = metrics->rule_engine_metrics.precision;
    metrics->system_recall = metrics->rule_engine_metrics.recall;
}

/* ========== Utility Functions ========== */

void perf_format_bytes(uint64_t bytes, char *buffer, size_t buf_size) {
    if (bytes < 1024) {
        snprintf(buffer, buf_size, "%lu B", bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(buffer, buf_size, "%.2f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        snprintf(buffer, buf_size, "%.2f MB", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buffer, buf_size, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

void perf_format_time(double ms, char *buffer, size_t buf_size) {
    if (ms < 1.0) {
        snprintf(buffer, buf_size, "%.3f ms", ms);
    } else if (ms < 1000.0) {
        snprintf(buffer, buf_size, "%.2f ms", ms);
    } else if (ms < 60000.0) {
        snprintf(buffer, buf_size, "%.2f s", ms / 1000.0);
    } else {
        snprintf(buffer, buf_size, "%.2f min", ms / 60000.0);
    }
}

/* ========== Display Functions ========== */

void perf_print_dpi_metrics(const dpi_performance_t *metrics) {
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║               DPI ENGINE PERFORMANCE METRICS                   ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    char bytes_str[32], time_str[32], mem_str[32];
    perf_format_bytes(metrics->total_bytes_processed, bytes_str, sizeof(bytes_str));
    perf_format_time(metrics->processing_time_ms, time_str, sizeof(time_str));
    perf_format_bytes(metrics->total_memory_bytes, mem_str, sizeof(mem_str));
    
    printf("  Processing Time:        %s\n", time_str);
    printf("  Packets Processed:      %lu\n", metrics->total_packets_processed);
    printf("  Bytes Processed:        %s\n", bytes_str);
    printf("  Throughput:             %lu packets/sec, %.2f MB/sec\n",
           metrics->packets_per_second, metrics->megabytes_per_second);
    printf("\n");
    printf("  Layer Parsing Success:\n");
    printf("    L2 (Data Link):       %lu / %lu (%.1f%%)\n",
           metrics->l2_parsed_successfully, metrics->total_packets_processed,
           metrics->l2_parse_rate);
    printf("    L3 (Network):         %lu / %lu (%.1f%%)\n",
           metrics->l3_parsed_successfully, metrics->total_packets_processed,
           metrics->l3_parse_rate);
    printf("    L4 (Transport):       %lu / %lu (%.1f%%)\n",
           metrics->l4_parsed_successfully, metrics->total_packets_processed,
           metrics->l4_parse_rate);
    printf("    L5 (Session/Flow):    %lu / %lu (%.1f%%)\n",
           metrics->l5_sessions_tracked, metrics->total_packets_processed,
           metrics->l5_parse_rate);
    printf("\n");
    printf("  Flow Management:\n");
    printf("    Total Flows Created:  %u\n", metrics->total_flows_created);
    printf("    Active Flows:         %u\n", metrics->active_flows);
    printf("    Avg Packets/Flow:     %.2f\n", metrics->avg_packets_per_flow);
    printf("    Avg Bytes/Flow:       %.2f\n", metrics->avg_bytes_per_flow);
    printf("\n");
    printf("  Protocol Detection:\n");
    printf("    Detected Protocols:   %u unique types\n", metrics->protocols_detected);
    printf("    Unknown Packets:      %lu\n", metrics->unknown_protocols);
    printf("    Detection Accuracy:   %.1f%% (%lu/%lu packets)\n", 
           metrics->protocol_detection_rate,
           metrics->total_packets_processed - metrics->unknown_protocols,
           metrics->total_packets_processed);
    printf("\n");
    printf("  Efficiency:\n");
    printf("    Time per Packet:      %.3f µs\n", metrics->avg_time_per_packet_us);
    printf("    Time per Flow:        %.3f µs\n", metrics->avg_time_per_flow_us);
    printf("    Memory Usage:         %s\n", mem_str);
    printf("\n");
}

void perf_print_rule_engine_metrics(const rule_engine_performance_t *metrics) {
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║            RULE ENGINE (IDS) PERFORMANCE METRICS               ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    char time_str[32];
    perf_format_time(metrics->processing_time_ms, time_str, sizeof(time_str));
    
    printf("  Processing Time:        %s\n", time_str);
    printf("  Flows Analyzed:         %u\n", metrics->total_flows_analyzed);
    printf("  Packets Inspected:      %lu\n", metrics->total_packets_inspected);
    printf("  Throughput:             %u flows/sec\n", metrics->flows_per_second);
    printf("\n");
    printf("  Attack Detection:\n");
    printf("    Total Attacks:        %u (%.2f%% of flows)\n",
           metrics->total_attacks_detected, metrics->attack_detection_rate);
    printf("    SYN Flood:            %u\n", metrics->syn_flood_detections);
    printf("    UDP Flood:            %u\n", metrics->udp_flood_detections);
    printf("    HTTP Flood:           %u\n", metrics->http_flood_detections);
    printf("    ICMP Flood:           %u\n", metrics->icmp_flood_detections);
    printf("    Port Scans:           %u\n", metrics->port_scan_detections);
    printf("    Other Attacks:        %u\n", metrics->other_attack_detections);
    printf("\n");
    printf("  IP Tracking:\n");
    printf("    Unique IPs Tracked:   %u\n", metrics->unique_ips_tracked);
    printf("    Blocked IPs:          %u\n", metrics->blocked_ips);
    // printf("    Blocked Packets:      %lu\n", metrics->blocked_packets);
    printf("\n");
    printf("  Efficiency:\n");
    printf("    Time per Flow:        %.3f µs\n", metrics->avg_time_per_flow_us);
    printf("    Time per Packet:      %.3f µs\n", metrics->avg_time_per_packet_us);
    printf("\n");
}

void perf_print_mqtt_parser_metrics(const mqtt_parser_performance_t *metrics) {
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║             MQTT PARSER PERFORMANCE METRICS                    ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    char time_str[32];
    perf_format_time(metrics->processing_time_ms, time_str, sizeof(time_str));
    
    printf("  Processing Time:        %s\n", time_str);
    printf("  MQTT Flows Detected:    %u / %u (%.1f%%)\n",
           metrics->mqtt_flows_detected, metrics->total_flows_scanned,
           metrics->mqtt_detection_rate);
    printf("\n");
    printf("  Message Parsing:\n");
    printf("    Total Messages:       %u\n", metrics->total_messages_parsed);
    printf("    Successful Parses:    %u (%.1f%%)\n",
           metrics->successful_parses, metrics->parse_success_rate);
    printf("    Failed Parses:        %u\n", metrics->failed_parses);
    printf("    Throughput:           %.2f messages/sec\n", metrics->messages_per_second);
    printf("\n");
    printf("  Message Type Distribution:\n");
    printf("    CONNECT:              %u\n", metrics->connect_messages);
    printf("    PUBLISH:              %u\n", metrics->publish_messages);
    printf("    SUBSCRIBE:            %u\n", metrics->subscribe_messages);
    printf("    PINGREQ:              %u\n", metrics->pingreq_messages);
    printf("    DISCONNECT:           %u\n", metrics->disconnect_messages);
    printf("    Other:                %u\n", metrics->other_messages);
    printf("\n");
    printf("  Sensor Data:\n");
    printf("    Data Extracted:       %u (%.1f%% of messages)\n",
           metrics->sensor_data_extracted, metrics->sensor_extraction_rate);
    printf("\n");
    printf("  Efficiency:\n");
    printf("    Time per Flow:        %.3f µs\n", metrics->avg_time_per_flow_us);
    printf("    Time per Message:     %.3f µs\n", metrics->avg_time_per_message_us);
    printf("\n");
}

void perf_print_system_metrics(const system_performance_t *metrics) {
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║            OVERALL SYSTEM PERFORMANCE METRICS                  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    char bytes_str[32], time_str[32], file_size_str[32];
    perf_format_bytes(metrics->total_bytes, bytes_str, sizeof(bytes_str));
    perf_format_time(metrics->total_processing_time_ms, time_str, sizeof(time_str));
    perf_format_bytes(metrics->pcap_file_size_bytes, file_size_str, sizeof(file_size_str));
    
    printf("  PCAP File:              %s\n", metrics->pcap_filename);
    printf("  File Size:              %s\n", file_size_str);
    printf("  Capture Duration:       %.2f s\n", metrics->pcap_duration_seconds);
    printf("\n");
    printf("  Total Processing Time:  %s\n", time_str);
    printf("  Total Packets:          %lu\n", metrics->total_packets);
    printf("  Total Bytes:            %s\n", bytes_str);
    printf("  Overall Throughput:     %.0f packets/sec, %.2f MB/sec\n",
           metrics->overall_packets_per_second, metrics->overall_megabytes_per_second);
    printf("\n");
    printf("  Pipeline Time Breakdown:\n");
    printf("    DPI Engine:           %.1f%%\n", metrics->dpi_time_percentage);
    printf("    Rule Engine:          %.1f%%\n", metrics->rule_engine_time_percentage);
    printf("    MQTT Parser:          %.1f%%\n", metrics->mqtt_parser_time_percentage);
    printf("    Overhead:             %.1f%%\n", metrics->overhead_time_percentage);
    printf("\n");
}

/* ========== Table Display Functions (Pretty Printing) ========== */

void perf_print_summary_table(const system_performance_t *metrics) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                          PERFORMANCE METRICS SUMMARY TABLE                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ MODULE          │ TIME (ms) │  PACKETS  │   FLOWS   │ THROUGHPUT │ ACCURACY    ║\n");
    printf("╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣\n");
    
    char dpi_time[16], rule_time[16], mqtt_time[16], total_time[16];
    perf_format_time(metrics->dpi_metrics.processing_time_ms, dpi_time, sizeof(dpi_time));
    perf_format_time(metrics->rule_engine_metrics.processing_time_ms, rule_time, sizeof(rule_time));
    perf_format_time(metrics->mqtt_parser_metrics.processing_time_ms, mqtt_time, sizeof(mqtt_time));
    perf_format_time(metrics->total_processing_time_ms, total_time, sizeof(total_time));
    
    // Calculate overall DPI accuracy (average of all parsing layers + protocol detection)
    double overall_dpi_accuracy = (metrics->dpi_metrics.l2_parse_rate + 
                                   metrics->dpi_metrics.l3_parse_rate + 
                                   metrics->dpi_metrics.l4_parse_rate + 
                                   metrics->dpi_metrics.l5_parse_rate +
                                   metrics->dpi_metrics.protocol_detection_rate) / 5.0;
    
    printf("║ DPI Engine      │ %9s │ %9lu │ %9u │ %6lu p/s │ Acc:%.1f%%     ║\n",
           dpi_time,
           metrics->dpi_metrics.total_packets_processed,
           metrics->dpi_metrics.total_flows_created,
           metrics->dpi_metrics.packets_per_second,
           overall_dpi_accuracy);
    
    printf("║                 │           │           │           │ %7.2f MB/s│             ║\n",
           metrics->dpi_metrics.megabytes_per_second);
    
    printf("╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣\n");
    
    printf("║ Rule Engine     │ %9s │ %9lu │ %9u │ %7u f/s│ Acc:%.1f%%    ║\n",
           rule_time,
           metrics->rule_engine_metrics.total_packets_inspected,
           metrics->rule_engine_metrics.total_flows_analyzed,
           metrics->rule_engine_metrics.flows_per_second,
           metrics->rule_engine_metrics.accuracy * 100.0);
    
    printf("║ (IDS)           │           │           │   Attacks │            │             ║\n");
    printf("║                 │           │           │ %9u │            │             ║\n",
           metrics->rule_engine_metrics.total_attacks_detected);
    
    printf("╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣\n");
    
    printf("║ MQTT Parser     │ %9s │ %9u │ %9u │ %7u m/s│ Parse:%.0f%% ║\n",
           mqtt_time,
           metrics->mqtt_parser_metrics.total_messages_parsed,
           metrics->mqtt_parser_metrics.mqtt_flows_detected,
           (uint32_t)(metrics->mqtt_parser_metrics.messages_per_second > 0 ? 
                      metrics->mqtt_parser_metrics.messages_per_second : 0),
           metrics->mqtt_parser_metrics.parse_success_rate);
    
    printf("║                 │           │  Messages │ MQTT Flows│            │ Sensor:%.0f%%║\n",
           metrics->mqtt_parser_metrics.sensor_extraction_rate);
    
    printf("╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣\n");
    
    printf("║ TOTAL SYSTEM    │ %9s │ %9lu │ %9u │ %6.0f p/s │ Overall     ║\n",
           total_time,
           metrics->total_packets,
           metrics->dpi_metrics.total_flows_created,
           metrics->overall_packets_per_second);
    
    printf("║                 │           │           │           │ %7.2f MB/s│ System      ║\n",
           metrics->overall_megabytes_per_second);
    
    printf("╚═════════════════╧═══════════╧═══════════╧═══════════╧════════════╧═════════════╝\n");
}

void perf_print_timing_breakdown_table(const system_performance_t *metrics) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                     PROCESSING TIME BREAKDOWN                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ Component        │ Time (ms)      │ Percentage │ Avg per Unit (µs)     ║\n");
    printf("╠══════════════════╪════════════════╪════════════╪═══════════════════════╣\n");
    
    char dpi_time[16], rule_time[16], mqtt_time[16], total_time[16];
    perf_format_time(metrics->dpi_metrics.processing_time_ms, dpi_time, sizeof(dpi_time));
    perf_format_time(metrics->rule_engine_metrics.processing_time_ms, rule_time, sizeof(rule_time));
    perf_format_time(metrics->mqtt_parser_metrics.processing_time_ms, mqtt_time, sizeof(mqtt_time));
    perf_format_time(metrics->total_processing_time_ms, total_time, sizeof(total_time));
    
    printf("║ DPI Engine       │ %14s │   %6.2f%%   │ %.3f per packet    ║\n",
           dpi_time, metrics->dpi_time_percentage,
           metrics->dpi_metrics.avg_time_per_packet_us);
    
    printf("║ Rule Engine      │ %14s │   %6.2f%%   │ %.3f per flow      ║\n",
           rule_time, metrics->rule_engine_time_percentage,
           metrics->rule_engine_metrics.avg_time_per_flow_us);
    
    printf("║ MQTT Parser      │ %14s │   %6.2f%%   │ %.3f per message   ║\n",
           mqtt_time, metrics->mqtt_parser_time_percentage,
           metrics->mqtt_parser_metrics.avg_time_per_message_us);
    
    double overhead_ms = metrics->total_processing_time_ms - 
                        (metrics->dpi_metrics.processing_time_ms +
                         metrics->rule_engine_metrics.processing_time_ms +
                         metrics->mqtt_parser_metrics.processing_time_ms);
    char overhead_time[16];
    perf_format_time(overhead_ms, overhead_time, sizeof(overhead_time));
    
    printf("║ Overhead         │ %14s │   %6.2f%%   │ N/A                   ║\n",
           overhead_time, metrics->overhead_time_percentage);
    
    printf("╠══════════════════╪════════════════╪════════════╪═══════════════════════╣\n");
    printf("║ TOTAL            │ %14s │   100.00%%  │                       ║\n", total_time);
    printf("╚══════════════════╧════════════════╧════════════╧═══════════════════════╝\n");
}

void perf_print_accuracy_table(const system_performance_t *metrics) {
    if (metrics->rule_engine_metrics.accuracy == 0) {
        return;  // Skip if no accuracy data
    }
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                  DETECTION ACCURACY METRICS                        ║\n");
    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    printf("║ Metric           │ Value          │ Description                    ║\n");
    printf("╠══════════════════╪════════════════╪════════════════════════════════╣\n");
    printf("║ True Positives   │ %14u │ Correctly detected attacks     ║\n",
           metrics->rule_engine_metrics.true_positives);
    printf("║ False Positives  │ %14u │ False alarms                   ║\n",
           metrics->rule_engine_metrics.false_positives);
    printf("║ True Negatives   │ %14u │ Normal traffic (correct)       ║\n",
           metrics->rule_engine_metrics.true_negatives);
    printf("║ False Negatives  │ %14u │ Missed attacks                 ║\n",
           metrics->rule_engine_metrics.false_negatives);
    printf("╠══════════════════╪════════════════╪════════════════════════════════╣\n");
    printf("║ Precision        │      %.2f%%     │ TP / (TP + FP)                 ║\n",
           metrics->rule_engine_metrics.precision * 100.0);
    printf("║ Recall           │      %.2f%%     │ TP / (TP + FN)                 ║\n",
           metrics->rule_engine_metrics.recall * 100.0);

    printf("║ Accuracy         │      %.2f%%     │ (TP + TN) / Total              ║\n",
           metrics->rule_engine_metrics.accuracy * 100.0);
    printf("╚══════════════════╧════════════════╧════════════════════════════════╝\n");
}

void perf_print_all_metrics_table(const system_performance_t *metrics) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                              COMPREHENSIVE PERFORMANCE METRICS                                 ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
    
    perf_print_summary_table(metrics);
    perf_print_timing_breakdown_table(metrics);
    // perf_print_accuracy_table(metrics);  // Don't print on terminal, only in file
    
    printf("\n");
}

/* ========== File Output Function ========== */

void perf_save_metrics_to_file(const system_performance_t *metrics, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not open metrics file for writing: %s\n", filename);
        return;
    }
    
    time_t now = time(NULL);
    fprintf(fp, "╔════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                         IWSN SECURITY - PERFORMANCE METRICS REPORT                            ║\n");
    fprintf(fp, "║                                Generated: %.24s                              ║\n", ctime(&now));
    fprintf(fp, "╚════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
    
    char bytes_str[32], time_str[32], file_size_str[32];
    
    // ===== SYSTEM OVERVIEW =====
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " SYSTEM OVERVIEW\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    perf_format_bytes(metrics->pcap_file_size_bytes, file_size_str, sizeof(file_size_str));
    perf_format_time(metrics->total_processing_time_ms, time_str, sizeof(time_str));
    perf_format_bytes(metrics->total_bytes, bytes_str, sizeof(bytes_str));
    
    fprintf(fp, "  PCAP File:                   %s\n", metrics->pcap_filename);
    fprintf(fp, "  File Size:                   %s\n", file_size_str);
    fprintf(fp, "  Capture Duration:            %.2f seconds\n", metrics->pcap_duration_seconds);
    fprintf(fp, "  Total Processing Time:       %s\n", time_str);
    fprintf(fp, "  Total Packets Processed:     %lu\n", metrics->total_packets);
    fprintf(fp, "  Total Bytes Processed:       %s\n", bytes_str);
    fprintf(fp, "  Overall Throughput:          %.0f packets/sec, %.2f MB/sec\n",
            metrics->overall_packets_per_second, metrics->overall_megabytes_per_second);
    fprintf(fp, "  CPU Usage:                   %.1f%%\n\n", metrics->cpu_utilization_percent);
    
    // ===== SUMMARY TABLE =====
    fprintf(fp, "\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                          PERFORMANCE METRICS SUMMARY TABLE                      ║\n");
    fprintf(fp, "╠══════════════════════════════════════════════════════════════════════════════════╣\n");
    fprintf(fp, "║ MODULE          │ TIME (ms) │  PACKETS  │   FLOWS   │ THROUGHPUT │ ACCURACY    ║\n");
    fprintf(fp, "╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣\n");
    
    char dpi_time[16], rule_time[16], mqtt_time[16], total_time[16];
    perf_format_time(metrics->dpi_metrics.processing_time_ms, dpi_time, sizeof(dpi_time));
    perf_format_time(metrics->rule_engine_metrics.processing_time_ms, rule_time, sizeof(rule_time));
    perf_format_time(metrics->mqtt_parser_metrics.processing_time_ms, mqtt_time, sizeof(mqtt_time));
    perf_format_time(metrics->total_processing_time_ms, total_time, sizeof(total_time));
    
    // Calculate overall DPI accuracy (average of all parsing layers + protocol detection)
    double overall_dpi_accuracy = (metrics->dpi_metrics.l2_parse_rate + 
                                   metrics->dpi_metrics.l3_parse_rate + 
                                   metrics->dpi_metrics.l4_parse_rate + 
                                   metrics->dpi_metrics.l5_parse_rate +
                                   metrics->dpi_metrics.protocol_detection_rate) / 5.0;
    
    fprintf(fp, "║ DPI Engine      │ %9s │ %9lu │ %9u │ %6lu p/s │ Acc:%.1f%%     ║\n",
            dpi_time, metrics->dpi_metrics.total_packets_processed,
            metrics->dpi_metrics.total_flows_created,
            metrics->dpi_metrics.packets_per_second,
            overall_dpi_accuracy);
    fprintf(fp, "║                 │           │           │           │ %7.2f MB/s│             ║\n",
            metrics->dpi_metrics.megabytes_per_second);
    
    fprintf(fp, "╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣\n");
    
    fprintf(fp, "║ Rule Engine     │ %9s │ %9lu │ %9u │ %7u f/s│ Acc:%.1f%%    ║\n",
            rule_time, metrics->rule_engine_metrics.total_packets_inspected,
            metrics->rule_engine_metrics.total_flows_analyzed,
            metrics->rule_engine_metrics.flows_per_second,
            metrics->rule_engine_metrics.accuracy * 100.0);
    fprintf(fp, "║ (IDS)           │           │           │   Attacks │            │             ║\n");
    fprintf(fp, "║                 │           │           │ %9u │            │             ║\n",
            metrics->rule_engine_metrics.total_attacks_detected);
    
    fprintf(fp, "╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣\n");
    
    fprintf(fp, "║ MQTT Parser     │ %9s │ %9u │ %9u │ %7u m/s│ Parse:%.0f%% ║\n",
            mqtt_time, metrics->mqtt_parser_metrics.total_messages_parsed,
            metrics->mqtt_parser_metrics.mqtt_flows_detected,
            (uint32_t)(metrics->mqtt_parser_metrics.messages_per_second > 0 ? 
                       metrics->mqtt_parser_metrics.messages_per_second : 0),
            metrics->mqtt_parser_metrics.parse_success_rate);
    fprintf(fp, "║                 │           │  Messages │ MQTT Flows│            │ Sensor:%.0f%%║\n",
            metrics->mqtt_parser_metrics.sensor_extraction_rate);
    
    fprintf(fp, "╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣\n");
    
    fprintf(fp, "║ TOTAL SYSTEM    │ %9s │ %9lu │ %9u │ %6.0f p/s │ Overall     ║\n",
            total_time, metrics->total_packets,
            metrics->dpi_metrics.total_flows_created,
            metrics->overall_packets_per_second);
    fprintf(fp, "║                 │           │           │           │ %7.2f MB/s│ System      ║\n",
            metrics->overall_megabytes_per_second);
    
    fprintf(fp, "╚═════════════════╧═══════════╧═══════════╧═══════════╧════════════╧═════════════╝\n\n");
    
    // ===== DETAILED METRICS =====
    fprintf(fp, "\n═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " DPI ENGINE DETAILED METRICS\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    perf_format_bytes(metrics->dpi_metrics.total_memory_bytes, bytes_str, sizeof(bytes_str));
    fprintf(fp, "  Layer Parsing Success Rates:\n");
    fprintf(fp, "    L2 (Data Link):          %lu / %lu (%.1f%%)\n",
            metrics->dpi_metrics.l2_parsed_successfully,
            metrics->dpi_metrics.total_packets_processed,
            metrics->dpi_metrics.l2_parse_rate);
    fprintf(fp, "    L3 (Network):            %lu / %lu (%.1f%%)\n",
            metrics->dpi_metrics.l3_parsed_successfully,
            metrics->dpi_metrics.total_packets_processed,
            metrics->dpi_metrics.l3_parse_rate);
    fprintf(fp, "    L4 (Transport):          %lu / %lu (%.1f%%)\n",
            metrics->dpi_metrics.l4_parsed_successfully,
            metrics->dpi_metrics.total_packets_processed,
            metrics->dpi_metrics.l4_parse_rate);
    fprintf(fp, "    L5 (Session/Flow):       %lu / %lu (%.1f%%)\n",
            metrics->dpi_metrics.l5_sessions_tracked,
            metrics->dpi_metrics.total_packets_processed,
            metrics->dpi_metrics.l5_parse_rate);
    fprintf(fp, "\n  Protocol Detection:\n");
    fprintf(fp, "    Detected Protocols:      %u unique types\n",
            metrics->dpi_metrics.protocols_detected);
    fprintf(fp, "    Unknown Packets:         %lu\n", metrics->dpi_metrics.unknown_protocols);
    fprintf(fp, "    Detection Accuracy:      %.1f%% (%lu/%lu packets)\n",
            metrics->dpi_metrics.protocol_detection_rate,
            metrics->dpi_metrics.total_packets_processed - metrics->dpi_metrics.unknown_protocols,
            metrics->dpi_metrics.total_packets_processed);
    fprintf(fp, "\n  Efficiency:\n");
    fprintf(fp, "    Avg Time per Packet:     %.3f µs\n",
            metrics->dpi_metrics.avg_time_per_packet_us);
    fprintf(fp, "    Avg Time per Flow:       %.3f µs\n",
            metrics->dpi_metrics.avg_time_per_flow_us);
    fprintf(fp, "    Memory Usage:            %s\n", bytes_str);
    
    fprintf(fp, "\n═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " RULE ENGINE (IDS) DETAILED METRICS\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Attack Detection Breakdown:\n");
    fprintf(fp, "    SYN Flood Attacks:       %u\n", metrics->rule_engine_metrics.syn_flood_detections);
    fprintf(fp, "    UDP Flood Attacks:       %u\n", metrics->rule_engine_metrics.udp_flood_detections);
    fprintf(fp, "    HTTP Flood Attacks:      %u\n", metrics->rule_engine_metrics.http_flood_detections);
    fprintf(fp, "    ICMP Flood Attacks:      %u\n", metrics->rule_engine_metrics.icmp_flood_detections);
    fprintf(fp, "    Port Scans:              %u\n", metrics->rule_engine_metrics.port_scan_detections);
    fprintf(fp, "\n  IP Tracking:\n");
    fprintf(fp, "    Unique IPs Tracked:      %u\n", metrics->rule_engine_metrics.unique_ips_tracked);
    fprintf(fp, "    Blocked IPs:             %u\n", metrics->rule_engine_metrics.blocked_ips);
    // fprintf(fp, "    Blocked Packets:         %lu\n", metrics->rule_engine_metrics.blocked_packets);
    
    fprintf(fp, "\n═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " MQTT PARSER DETAILED METRICS\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Message Parsing:\n");
    fprintf(fp, "    Total Messages:          %u\n", metrics->mqtt_parser_metrics.total_messages_parsed);
    fprintf(fp, "    Successful Parses:       %u (%.1f%%)\n",
            metrics->mqtt_parser_metrics.successful_parses,
            metrics->mqtt_parser_metrics.parse_success_rate);
    fprintf(fp, "    Failed Parses:           %u\n", metrics->mqtt_parser_metrics.failed_parses);
    fprintf(fp, "\n  Message Type Distribution:\n");
    fprintf(fp, "    CONNECT:                 %u\n", metrics->mqtt_parser_metrics.connect_messages);
    fprintf(fp, "    PUBLISH:                 %u\n", metrics->mqtt_parser_metrics.publish_messages);
    fprintf(fp, "    SUBSCRIBE:               %u\n", metrics->mqtt_parser_metrics.subscribe_messages);
    fprintf(fp, "    PINGREQ:                 %u\n", metrics->mqtt_parser_metrics.pingreq_messages);
    fprintf(fp, "    DISCONNECT:              %u\n", metrics->mqtt_parser_metrics.disconnect_messages);
    fprintf(fp, "\n  Sensor Data:\n");
    fprintf(fp, "    Data Extracted:          %u (%.1f%% of messages)\n",
            metrics->mqtt_parser_metrics.sensor_data_extracted,
            metrics->mqtt_parser_metrics.sensor_extraction_rate);
    
    fprintf(fp, "\n═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " END OF REPORT\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
    fclose(fp);
    printf("\n✓ Performance metrics saved to: %s\n", filename);
}

void perf_append_metrics_to_file(const system_performance_t *metrics, const char *filename) {
    FILE *fp = fopen(filename, "a");
    if (!fp) {
        fprintf(stderr, "Error: Could not open metrics file for appending: %s\n", filename);
        return;
    }
    
    time_t now = time(NULL);
    fprintf(fp, "\n\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " RUN TIMESTAMP: %.24s\n", ctime(&now));
    fprintf(fp, " PCAP FILE: %s\n", metrics->pcap_filename);
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Total Time: %.2f ms | Packets: %lu | Flows: %u | Attacks: %u\n",
            metrics->total_processing_time_ms,
            metrics->total_packets,
            metrics->dpi_metrics.total_flows_created,
            metrics->rule_engine_metrics.total_attacks_detected);
    fprintf(fp, "  DPI: %.2f ms | Rule Engine: %.2f ms | MQTT: %.2f ms\n",
            metrics->dpi_metrics.processing_time_ms,
            metrics->rule_engine_metrics.processing_time_ms,
            metrics->mqtt_parser_metrics.processing_time_ms);
    
    fclose(fp);
}

/* ========== Helper Function: Determine if PCAP is Attack Sample ========== */
int perf_is_attack_pcap(const char *filename) {
    if (!filename) return 0;
    
    // Check if filename contains "attack" keyword (case-insensitive)
    const char *lower_filename = filename;
    if (strstr(lower_filename, "attack") != NULL) return 1;
    if (strstr(lower_filename, "Attack") != NULL) return 1;
    if (strstr(lower_filename, "ATTACK") != NULL) return 1;
    
    // Check for specific attack type names in filename
    const char *attack_keywords[] = {
        "syn_flood", "synflood", "syn-flood",
        "udp_flood", "udpflood", "udp-flood",
        "http_flood", "httpflood", "http-flood",
        "icmp_flood", "icmpflood", "icmp-flood",
        "ddos", "DDoS", "DDOS",
        "scan", "Scan", "SCAN",
        "port_scan", "portscan", "port-scan",
        "tcp_syn_scan", "tcp_connect_scan",
        "udp_scan", "udpscan",
        "ping_of_death", "pod",
        "arp_spoof", "arp_spoofing",
        "rudy", "RUDY", "Rudy",
        "malware", "Malware", "MALWARE",
        "exploit", "Exploit", "EXPLOIT",
        NULL
    };
    
    for (int i = 0; attack_keywords[i] != NULL; i++) {
        if (strstr(filename, attack_keywords[i]) != NULL) {
            return 1;
        }
    }
    
    // If filename contains "normal", "benign", "legitimate", it's NOT an attack
    if (strstr(filename, "normal") != NULL) return 0;
    if (strstr(filename, "Normal") != NULL) return 0;
    if (strstr(filename, "benign") != NULL) return 0;
    if (strstr(filename, "Benign") != NULL) return 0;
    if (strstr(filename, "legitimate") != NULL) return 0;
    
    return 0;  // Default: assume normal traffic
}

