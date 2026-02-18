/*
 * IWSN Security - Performance Metrics Module
 * Comprehensive performance tracking for all components:
 * - DPI Engine (Layer 2-7 parsing)
 * - Rule Engine (Attack Detection)
 * - MQTT Parser (Protocol-specific analysis)
 */

#ifndef PERFORMANCE_METRICS_H
#define PERFORMANCE_METRICS_H

#include <stdint.h>
#include <sys/time.h>
#include <time.h>

/* ========== DPI Engine Performance Metrics ========== */
typedef struct {
    // Timing
    struct timeval start_time;
    struct timeval end_time;
    double processing_time_ms;
    
    // Packet Processing
    uint64_t total_packets_processed;
    uint64_t total_bytes_processed;
    uint64_t packets_per_second;
    double megabytes_per_second;
    
    // Layer Parsing Success Rates
    uint64_t l2_parsed_successfully;
    uint64_t l3_parsed_successfully;
    uint64_t l4_parsed_successfully;
    uint64_t l5_sessions_tracked;
    double l2_parse_rate;    // Percentage
    double l3_parse_rate;
    double l4_parse_rate;
    double l5_parse_rate;
    
    // Flow Management
    uint32_t total_flows_created;
    uint32_t active_flows;
    double avg_packets_per_flow;
    double avg_bytes_per_flow;
    
    // Protocol Detection (nDPI)
    uint32_t protocols_detected;     // Number of unique protocol types identified
    uint64_t unknown_protocols;      // Number of packets with unknown protocols
    double protocol_detection_rate;  // (detected_packets / total_packets) * 100
    
    // Memory Usage
    uint64_t memory_flows_bytes;
    uint64_t memory_packets_bytes;
    uint64_t total_memory_bytes;
    
    // Efficiency Metrics
    double avg_time_per_packet_us;   // Microseconds
    double avg_time_per_flow_us;
    
    // CPU Usage
    double cpu_usage_percent;        // CPU usage percentage
    
} dpi_performance_t;

/* ========== Rule Engine Performance Metrics ========== */
typedef struct {
    // Timing
    struct timeval start_time;
    struct timeval end_time;
    double processing_time_ms;
    
    // Analysis Metrics
    uint32_t total_flows_analyzed;
    uint64_t total_packets_inspected;
    uint32_t flows_per_second;
    
    // Attack Detection
    uint32_t total_attacks_detected;
    uint32_t attacks_by_type[20];    // Per attack type
    uint32_t malicious_flows_detected;  // Flows containing attacks
    double attack_detection_rate;    // % of malicious flows detected
    uint32_t is_attack_pcap;         // Ground truth: 1 if attack file, 0 if normal
    
    // Detection Accuracy (if ground truth available)
    uint32_t true_positives;
    uint32_t false_positives;
    uint32_t true_negatives;
    uint32_t false_negatives;
    double precision;      // TP / (TP + FP)
    double recall;         // TP / (TP + FN)
    double f1_score;       // 2 * (precision * recall) / (precision + recall)
    double accuracy;       // (TP + TN) / (TP + TN + FP + FN)
    
    // IP Tracking
    uint32_t unique_ips_tracked;
    uint32_t blocked_ips;
    uint64_t blocked_packets;
    
    // Efficiency Metrics
    double avg_time_per_flow_us;
    double avg_time_per_packet_us;
    
    // Rule Engine Statistics
    uint32_t syn_flood_detections;
    uint32_t udp_flood_detections;
    uint32_t http_flood_detections;
    uint32_t port_scan_detections;
    uint32_t icmp_flood_detections;
    uint32_t other_attack_detections;
    
} rule_engine_performance_t;

/* ========== MQTT Parser Performance Metrics ========== */
typedef struct {
    // Timing
    struct timeval start_time;
    struct timeval end_time;
    double processing_time_ms;
    
    // MQTT Flow Detection
    uint32_t mqtt_flows_detected;
    uint32_t total_flows_scanned;
    double mqtt_detection_rate;  // Percentage
    
    // Message Parsing
    uint32_t total_messages_parsed;
    uint32_t successful_parses;
    uint32_t failed_parses;
    double parse_success_rate;   // Percentage
    
    // Message Type Distribution
    uint32_t connect_messages;
    uint32_t publish_messages;
    uint32_t subscribe_messages;
    uint32_t pingreq_messages;
    uint32_t disconnect_messages;
    uint32_t other_messages;
    
    // Sensor Data Extraction
    uint32_t sensor_data_extracted;
    double sensor_extraction_rate;  // Per message
    
    // Anomaly Detection
    uint32_t anomalies_detected;
    uint32_t malformed_packets;
    uint32_t oversized_packets;
    
    // Efficiency Metrics
    double avg_time_per_flow_us;
    double avg_time_per_message_us;
    double messages_per_second;
    
} mqtt_parser_performance_t;

/* ========== Overall System Performance Metrics ========== */
typedef struct {
    // Component Metrics
    dpi_performance_t dpi_metrics;
    rule_engine_performance_t rule_engine_metrics;
    mqtt_parser_performance_t mqtt_parser_metrics;
    
    // End-to-End Timing
    struct timeval system_start_time;
    struct timeval system_end_time;
    double total_processing_time_ms;
    
    // Overall Throughput
    uint64_t total_packets;
    uint64_t total_bytes;
    double overall_packets_per_second;
    double overall_megabytes_per_second;
    
    // Pipeline Efficiency
    double dpi_time_percentage;
    double rule_engine_time_percentage;
    double mqtt_parser_time_percentage;
    double overhead_time_percentage;
    
    // System Resource Usage
    uint64_t peak_memory_usage_bytes;
    double cpu_utilization_percent;
    
    // Overall Accuracy (if ground truth available)
    double system_accuracy;
    double system_precision;
    double system_recall;
    
    // PCAP File Information
    char pcap_filename[256];
    uint64_t pcap_file_size_bytes;
    double pcap_duration_seconds;
    
} system_performance_t;

/* ========== Function Prototypes ========== */

// === Initialization ===
void perf_metrics_init(system_performance_t *metrics);
void perf_dpi_init(dpi_performance_t *metrics);
void perf_rule_engine_init(rule_engine_performance_t *metrics);
void perf_mqtt_parser_init(mqtt_parser_performance_t *metrics);

// === Timing Functions ===
void perf_start_timer(struct timeval *start);
double perf_end_timer(struct timeval *start, struct timeval *end);
double perf_calculate_elapsed_ms(struct timeval *start, struct timeval *end);

// === DPI Metrics Update ===
void perf_dpi_update(dpi_performance_t *metrics, const void *dpi_engine);
void perf_dpi_finalize(dpi_performance_t *metrics);

// === Rule Engine Metrics Update ===
void perf_rule_engine_update(rule_engine_performance_t *metrics, const void *rule_engine);
void perf_rule_engine_finalize(rule_engine_performance_t *metrics, const void *rule_engine);

// === MQTT Parser Metrics Update ===
void perf_mqtt_parser_update(mqtt_parser_performance_t *metrics, 
                             uint32_t mqtt_flows, uint32_t total_flows,
                             uint32_t messages_parsed, uint32_t successful,
                             uint32_t sensor_data_count);
void perf_mqtt_parser_finalize(mqtt_parser_performance_t *metrics);

// === System-wide Metrics ===
void perf_system_finalize(system_performance_t *metrics);
void perf_system_calculate_percentages(system_performance_t *metrics);

// === Display Functions ===
void perf_print_dpi_metrics(const dpi_performance_t *metrics);
void perf_print_rule_engine_metrics(const rule_engine_performance_t *metrics);
void perf_print_mqtt_parser_metrics(const mqtt_parser_performance_t *metrics);
void perf_print_system_metrics(const system_performance_t *metrics);

// === Table Display (Pretty Printing) ===
void perf_print_all_metrics_table(const system_performance_t *metrics);
void perf_print_summary_table(const system_performance_t *metrics);
void perf_print_timing_breakdown_table(const system_performance_t *metrics);
void perf_print_accuracy_table(const system_performance_t *metrics);

// === File Output ===
void perf_save_metrics_to_file(const system_performance_t *metrics, const char *filename);
void perf_append_metrics_to_file(const system_performance_t *metrics, const char *filename);

// === Utility Functions ===
void perf_format_bytes(uint64_t bytes, char *buffer, size_t buf_size);
void perf_format_time(double ms, char *buffer, size_t buf_size);
const char* perf_get_attack_type_name(int attack_type);
// Helper function to determine if PCAP file is an attack sample (based on filename)
int perf_is_attack_pcap(const char *filename);
#endif /* PERFORMANCE_METRICS_H */
