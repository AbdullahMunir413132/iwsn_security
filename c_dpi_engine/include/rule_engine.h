/*
 * IWSN Security - Rule-Based Intrusion Detection Engine
 * Detects various network attacks using statistical analysis and pattern matching
 */

#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <stdint.h>
#include <time.h>
#include "dpi_engine.h"

/* ========== Attack Types ========== */
typedef enum {
    ATTACK_NONE = 0,
    ATTACK_SYN_FLOOD,
    ATTACK_UDP_FLOOD,
    ATTACK_HTTP_FLOOD,
    ATTACK_PING_OF_DEATH,
    ATTACK_ARP_SPOOFING,
    ATTACK_RUDY,
    ATTACK_TCP_SYN_SCAN,
    ATTACK_TCP_CONNECT_SCAN,
    ATTACK_UDP_SCAN,
    ATTACK_PORT_SCAN_GENERIC,
    ATTACK_ICMP_FLOOD,
    ATTACK_MULTIPLE  // Multiple attacks detected
} attack_type_t;

/* ========== Attack Severity ========== */
typedef enum {
    SEVERITY_INFO = 0,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL
} attack_severity_t;

/* ========== Detection Thresholds Configuration ========== */
typedef struct {
    // SYN Flood Detection
    uint32_t syn_flood_threshold;           // SYN packets per second
    double syn_flood_ratio;                 // SYN/ACK ratio threshold
    uint32_t syn_flood_time_window;         // Time window in seconds
    
    // UDP Flood Detection
    uint32_t udp_flood_threshold;           // UDP packets per second
    uint32_t udp_flood_time_window;         // Time window in seconds
    uint32_t udp_flood_packet_count;        // Min packets to trigger
    
    // HTTP Flood Detection
    uint32_t http_flood_threshold;          // HTTP requests per second
    uint32_t http_flood_time_window;        // Time window in seconds
    
    // Ping of Death Detection
    uint32_t pod_packet_size;               // ICMP packet size threshold
    
    // ARP Spoofing Detection
    uint32_t arp_spoofing_mac_changes;      // MAC changes per IP
    uint32_t arp_spoofing_time_window;      // Time window in seconds
    
    // RUDY (Slow POST) Detection
    double rudy_avg_body_rate;              // Bytes per second threshold
    uint32_t rudy_min_packets;              // Minimum packets to analyze
    uint32_t rudy_time_window;              // Time window in seconds
    
    // Port Scan Detection
    uint32_t port_scan_unique_ports;        // Unique ports threshold
    uint32_t port_scan_time_window;         // Time window in seconds
    double port_scan_connection_ratio;      // Failed/total connection ratio
    
    // TCP Connect Scan Detection
    uint32_t tcp_connect_scan_ports;        // Unique ports threshold
    double tcp_connect_scan_completion;     // Connection completion ratio
    
    // ICMP Flood Detection
    uint32_t icmp_flood_threshold;          // ICMP packets per second
    uint32_t icmp_flood_time_window;        // Time window in seconds
    
} detection_thresholds_t;

/* ========== Attack Detection Result ========== */
typedef struct {
    attack_type_t attack_type;
    attack_severity_t severity;
    char attack_name[64];
    char description[256];
    double confidence_score;  // 0.0 to 1.0
    
    // Attack source information
    uint32_t attacker_ip;
    uint32_t target_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    // Attack metrics
    uint64_t packet_count;
    uint64_t byte_count;
    double packets_per_second;
    double duration_seconds;
    
    // Additional details
    char details[512];
    
    // Timestamp
    struct timeval detection_time;
    
} attack_detection_t;

/* ========== Per-IP Statistics (for tracking individual hosts) ========== */
typedef struct {
    uint32_t ip_address;
    
    // Connection statistics
    uint32_t total_syn_packets;
    uint32_t total_syn_ack_packets;
    uint32_t total_ack_packets;
    uint32_t total_udp_packets;
    uint32_t total_icmp_packets;
    uint32_t total_http_requests;
    
    // Port scanning indicators
    uint16_t unique_dst_ports[1024];
    uint32_t unique_dst_port_count;
    uint32_t failed_connections;
    uint32_t successful_connections;
    
    // ARP-related
    uint8_t mac_addresses[10][6];
    uint32_t mac_address_count;
    
    // Timing information
    struct timeval first_seen;
    struct timeval last_seen;
    
} ip_statistics_t;

/* ========== Rule Engine Context ========== */
typedef struct {
    // Detection thresholds
    detection_thresholds_t thresholds;
    
    // Per-IP tracking
    ip_statistics_t *ip_stats;
    uint32_t ip_stats_count;
    uint32_t max_ips;
    
    // Detected attacks
    attack_detection_t *detections;
    uint32_t detection_count;
    uint32_t max_detections;
    
    // IP Blocklist (for detected attackers)
    uint32_t *blocked_ips;
    uint32_t blocked_ip_count;
    uint32_t max_blocked_ips;
    uint64_t blocked_packet_count;
    
    // Global statistics
    uint64_t total_packets_analyzed;
    uint64_t total_attacks_detected;
    uint64_t attacks_by_type[20];
    
    // Analysis time window
    struct timeval analysis_start_time;
    struct timeval analysis_end_time;
    
} rule_engine_t;

/* ========== Function Prototypes ========== */

// Engine initialization and cleanup
rule_engine_t* rule_engine_init(void);
void rule_engine_destroy(rule_engine_t *engine);
void rule_engine_set_default_thresholds(rule_engine_t *engine);

// Per-packet analysis
void rule_engine_analyze_packet(rule_engine_t *engine, const parsed_packet_t *packet);

// Per-flow analysis
void rule_engine_analyze_flow(rule_engine_t *engine, const flow_stats_t *flow);

// Batch analysis (analyze all flows at once)
void rule_engine_analyze_all_flows(rule_engine_t *engine, const dpi_engine_t *dpi_engine);

// Individual attack detection functions
int detect_syn_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
void detect_aggregate_syn_flood(rule_engine_t *engine, const dpi_engine_t *dpi_engine);
int detect_udp_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_http_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_ping_of_death(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_arp_spoofing(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_rudy_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_tcp_syn_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_tcp_connect_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_udp_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_icmp_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);

// IP statistics management
ip_statistics_t* get_or_create_ip_stats(rule_engine_t *engine, uint32_t ip_address);
void update_ip_statistics(rule_engine_t *engine, const parsed_packet_t *packet);

// IP Blocking functions
void block_ip(rule_engine_t *engine, uint32_t ip_address);
int is_ip_blocked(rule_engine_t *engine, uint32_t ip_address);
void check_and_block_flood_sources(rule_engine_t *engine);

// Reporting functions
void print_attack_detection(const attack_detection_t *detection);
void print_attack_summary(const rule_engine_t *engine);
void generate_attack_report(const rule_engine_t *engine, const char *output_file);
void print_detailed_attack_analysis(const rule_engine_t *engine);

// Utility functions
const char* attack_type_to_string(attack_type_t type);
const char* severity_to_string(attack_severity_t severity);
const char* get_severity_color(attack_severity_t severity);
void add_detection(rule_engine_t *engine, const attack_detection_t *detection);

#endif /* RULE_ENGINE_H */
