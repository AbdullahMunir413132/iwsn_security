/*
 * IWSN Security - Rule-Based Intrusion Detection Engine
 * RFC-Compliant Attack Detection with International Standards
 * 
 * Standards References:
 *   RFC 793  - TCP Protocol Specification
 *   RFC 791  - IPv4 Protocol Specification 
 *   RFC 792  - ICMP Protocol Specification
 *   RFC 768  - UDP Protocol Specification
 *   RFC 826  - ARP Protocol Specification
 *   RFC 4987 - TCP SYN Flooding Attacks and Common Mitigations
 *   RFC 6274 - Security Assessment of IPv4
 *   RFC 2827 - Network Ingress Filtering (BCP 38)
 *   RFC 4732 - Internet Denial-of-Service Considerations
 *   RFC 5358 - Preventing Use of Recursive Nameservers
 *   RFC 5905 - NTP Version 4 Specification
 *   RFC 9110 - HTTP Semantics
 *   RFC 5227 - IPv4 Address Conflict Detection
 *   NIST SP 800-94 - Guide to IDPS
 */

#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <stdint.h>
#include <time.h>
#include "dpi_engine.h"

/* ========== Attack Types (21 RFC-Referenced Types) ========== */
typedef enum {
    ATTACK_NONE = 0,
    
    /* --- Volumetric / Flooding Attacks --- */
    ATTACK_SYN_FLOOD,          /* RFC 4987, RFC 793 */
    ATTACK_UDP_FLOOD,          /* RFC 768, RFC 4732 */
    ATTACK_HTTP_FLOOD,         /* RFC 9110, RFC 4732 */
    ATTACK_ICMP_FLOOD,         /* RFC 792, RFC 4732 */
    ATTACK_DNS_AMPLIFICATION,  /* RFC 5358, RFC 5625 */
    ATTACK_NTP_AMPLIFICATION,  /* RFC 5905, CVE-2013-5211 */
    ATTACK_SMURF,              /* RFC 2827 (BCP 38), RFC 6274 */
    ATTACK_FRAGGLE,            /* RFC 768, RFC 6274 */
    
    /* --- Protocol Exploitation Attacks --- */
    ATTACK_PING_OF_DEATH,      /* RFC 791 §3.2, RFC 6274 §5.3 */
    ATTACK_LAND_ATTACK,        /* RFC 6274, CVE-1999-0016 */
    ATTACK_TEARDROP,           /* RFC 791 §3.2, RFC 6274 */
    ATTACK_IP_SPOOFING,        /* RFC 2827 (BCP 38) */
    
    /* --- Reconnaissance / Scanning Attacks --- */
    ATTACK_TCP_SYN_SCAN,       /* RFC 793, Nmap reference */
    ATTACK_TCP_CONNECT_SCAN,   /* RFC 793, Nmap reference */
    ATTACK_UDP_SCAN,           /* RFC 768, Nmap reference */
    ATTACK_XMAS_SCAN,          /* RFC 793 §3.9 */
    ATTACK_NULL_SCAN,          /* RFC 793 §3.9 */
    ATTACK_FIN_SCAN,           /* RFC 793 §3.9 */
    ATTACK_PORT_SCAN_GENERIC,  /* General port scanning */
    
    /* --- Application-Layer Attacks --- */
    ATTACK_RUDY,               /* RFC 9110, OWASP */
    ATTACK_SLOWLORIS,          /* RFC 9110, OWASP */
    
    /* --- Layer 2 Attacks --- */
    ATTACK_ARP_SPOOFING,       /* RFC 826, RFC 5227 */
    
    ATTACK_MULTIPLE,           /* Multiple attacks detected */
    ATTACK_TYPE_COUNT          /* Sentinel for array sizing */
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
/* All threshold values are derived from RFC recommendations and industry best practices */
typedef struct {
    /* --- SYN Flood Detection (RFC 4987) --- */
    uint32_t syn_flood_threshold;           /* SYN packets per second */
    double syn_flood_ratio;                 /* SYN/ACK ratio threshold */
    uint32_t syn_flood_time_window;         /* Time window in seconds */
    
    /* --- UDP Flood Detection (RFC 4732) --- */
    uint32_t udp_flood_threshold;           /* UDP packets per second */
    uint32_t udp_flood_time_window;         /* Time window in seconds */
    uint32_t udp_flood_packet_count;        /* Min packets to trigger */
    
    /* --- HTTP Flood Detection (RFC 9110) --- */
    uint32_t http_flood_threshold;          /* HTTP requests per second */
    uint32_t http_flood_time_window;        /* Time window in seconds */
    
    /* --- ICMP Flood Detection (RFC 792) --- */
    uint32_t icmp_flood_threshold;          /* ICMP packets per second */
    uint32_t icmp_flood_time_window;        /* Time window in seconds */
    
    /* --- Ping of Death Detection (RFC 791 §3.2) --- */
    uint32_t pod_packet_size;               /* ICMP packet size threshold (>65535 per RFC) */
    
    /* --- ARP Spoofing Detection (RFC 826, RFC 5227) --- */
    uint32_t arp_spoofing_mac_changes;      /* MAC changes per IP */
    uint32_t arp_spoofing_time_window;      /* Time window in seconds */
    
    /* --- RUDY / Slow POST Detection (RFC 9110) --- */
    double rudy_avg_body_rate;              /* Bytes per second threshold */
    uint32_t rudy_min_packets;              /* Minimum packets to analyze */
    uint32_t rudy_time_window;              /* Time window in seconds */
    
    /* --- Slowloris Detection (RFC 9110) --- */
    double slowloris_header_rate;           /* Header bytes per second threshold */
    uint32_t slowloris_min_duration;        /* Min connection duration (seconds) */
    uint32_t slowloris_min_connections;     /* Min concurrent slow connections */
    
    /* --- Port Scan Detection (General) --- */
    uint32_t port_scan_unique_ports;        /* Unique ports threshold */
    uint32_t port_scan_time_window;         /* Time window in seconds */
    double port_scan_connection_ratio;      /* Failed/total connection ratio */
    
    /* --- TCP Connect Scan Detection --- */
    uint32_t tcp_connect_scan_ports;        /* Unique ports threshold */
    double tcp_connect_scan_completion;     /* Connection completion ratio */
    
    /* --- Xmas/NULL/FIN Scan Detection (RFC 793 §3.9) --- */
    uint32_t stealth_scan_port_threshold;   /* Min unique ports for stealth scans */
    
    /* --- Land Attack Detection (RFC 6274) --- */
    /* No configurable threshold — deterministic check: src_ip==dst_ip && src_port==dst_port */
    
    /* --- Smurf Attack Detection (BCP 38) --- */
    uint32_t smurf_icmp_threshold;          /* ICMP echo requests to broadcast per second */
    
    /* --- Fraggle Attack Detection (RFC 6274) --- */
    uint32_t fraggle_udp_threshold;         /* UDP packets to broadcast ports per second */
    
    /* --- Teardrop Detection (RFC 791 §3.2) --- */
    /* No configurable threshold — deterministic check: overlapping fragment offsets */
    
    /* --- DNS Amplification Detection (RFC 5358) --- */
    uint32_t dns_amp_response_size;         /* DNS response size threshold (bytes) */
    uint32_t dns_amp_rate_threshold;        /* DNS responses per second */
    
    /* --- NTP Amplification Detection (RFC 5905, CVE-2013-5211) --- */
    uint32_t ntp_amp_response_size;         /* NTP response size threshold (bytes) */
    uint32_t ntp_amp_rate_threshold;        /* NTP responses per second */
    
    /* --- IP Spoofing Detection (BCP 38) --- */
    /* Deterministic checks on impossible source addresses */
    
} detection_thresholds_t;

/* ========== Attack Detection Result ========== */
typedef struct {
    attack_type_t attack_type;
    attack_severity_t severity;
    char attack_name[64];
    char description[256];
    double confidence_score;  /* 0.0 to 1.0 */
    
    /* RFC reference for this detection */
    char rfc_reference[128];
    
    /* Attack source information */
    uint32_t attacker_ip;
    uint32_t target_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    /* Attack metrics */
    uint64_t packet_count;
    uint64_t byte_count;
    double packets_per_second;
    double duration_seconds;
    
    /* Additional details */
    char details[512];
    
    /* Timestamp */
    struct timeval detection_time;
    
} attack_detection_t;

/* ========== Per-IP Statistics (for tracking individual hosts) ========== */
typedef struct {
    uint32_t ip_address;
    
    /* Connection statistics */
    uint32_t total_syn_packets;
    uint32_t total_syn_ack_packets;
    uint32_t total_ack_packets;
    uint32_t total_udp_packets;
    uint32_t total_icmp_packets;
    uint32_t total_http_requests;
    
    /* Port scanning indicators */
    uint16_t unique_dst_ports[1024];
    uint32_t unique_dst_port_count;
    uint32_t failed_connections;
    uint32_t successful_connections;
    
    /* ARP-related */
    uint8_t mac_addresses[10][6];
    uint32_t mac_address_count;
    
    /* Timing information */
    struct timeval first_seen;
    struct timeval last_seen;
    
} ip_statistics_t;

/* ========== Rule Engine Context ========== */
typedef struct {
    /* Detection thresholds */
    detection_thresholds_t thresholds;
    
    /* Per-IP tracking */
    ip_statistics_t *ip_stats;
    uint32_t ip_stats_count;
    uint32_t max_ips;
    
    /* Detected attacks */
    attack_detection_t *detections;
    uint32_t detection_count;
    uint32_t max_detections;
    
    /* IP Blocklist (for detected attackers) */
    uint32_t *blocked_ips;
    uint32_t blocked_ip_count;
    uint32_t max_blocked_ips;
    uint64_t blocked_packet_count;
    
    /* Global statistics */
    uint64_t total_packets_analyzed;
    uint64_t total_attacks_detected;
    uint64_t attacks_by_type[ATTACK_TYPE_COUNT];
    
    /* Analysis time window */
    struct timeval analysis_start_time;
    struct timeval analysis_end_time;
    
} rule_engine_t;

/* ========== Function Prototypes ========== */

/* Engine initialization and cleanup */
rule_engine_t* rule_engine_init(void);
void rule_engine_destroy(rule_engine_t *engine);
void rule_engine_set_default_thresholds(rule_engine_t *engine);

/* Per-packet analysis */
void rule_engine_analyze_packet(rule_engine_t *engine, const parsed_packet_t *packet);

/* Per-flow analysis */
void rule_engine_analyze_flow(rule_engine_t *engine, const flow_stats_t *flow);

/* Batch analysis (analyze all flows at once) */
void rule_engine_analyze_all_flows(rule_engine_t *engine, const dpi_engine_t *dpi_engine);

/* ARP batch pre-processing (second pass over PCAP to extract ARP sender mappings) */
void rule_engine_process_arp_pcap(rule_engine_t *engine, const char *pcap_file);

/* ========== Individual Attack Detection Functions ========== */

/* Volumetric / Flooding */
int detect_syn_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
void detect_aggregate_syn_flood(rule_engine_t *engine, const dpi_engine_t *dpi_engine);
int detect_udp_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_http_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_icmp_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_dns_amplification(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_ntp_amplification(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_smurf_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_fraggle_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);

/* Protocol Exploitation */
int detect_ping_of_death(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_land_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_teardrop_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_ip_spoofing(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);

/* Reconnaissance / Scanning */
int detect_tcp_syn_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_tcp_connect_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_udp_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_xmas_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_null_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_fin_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);

/* Application-Layer */
int detect_rudy_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);
int detect_slowloris(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);

/* Layer 2 */
int detect_arp_spoofing(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection);

/* IP statistics management */
ip_statistics_t* get_or_create_ip_stats(rule_engine_t *engine, uint32_t ip_address);
void update_ip_statistics(rule_engine_t *engine, const parsed_packet_t *packet);

/* IP Blocking functions */
void block_ip(rule_engine_t *engine, uint32_t ip_address);
int is_ip_blocked(rule_engine_t *engine, uint32_t ip_address);
void check_and_block_flood_sources(rule_engine_t *engine);

/* Reporting functions */
void print_attack_detection(const attack_detection_t *detection);
void print_attack_summary(const rule_engine_t *engine);
void generate_attack_report(const rule_engine_t *engine, const char *output_file);
void print_detailed_attack_analysis(const rule_engine_t *engine);

/* Utility functions */
const char* attack_type_to_string(attack_type_t type);
const char* severity_to_string(attack_severity_t severity);
const char* get_severity_color(attack_severity_t severity);
const char* get_rfc_reference(attack_type_t type);
void add_detection(rule_engine_t *engine, const attack_detection_t *detection);

#endif /* RULE_ENGINE_H */
