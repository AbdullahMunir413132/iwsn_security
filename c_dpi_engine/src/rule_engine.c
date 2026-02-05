/*
 * Rule Engine - Main Implementation
 * Core functions for attack detection and analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include "rule_engine.h"

/* ========== Engine Initialization ========== */

rule_engine_t* rule_engine_init(void) {
    rule_engine_t *engine = calloc(1, sizeof(rule_engine_t));
    if (!engine) {
        fprintf(stderr, "[Rule Engine] Failed to allocate memory\n");
        return NULL;
    }
    
    // Set default thresholds
    rule_engine_set_default_thresholds(engine);
    
    // Allocate IP statistics table
    engine->max_ips = 10000;
    engine->ip_stats = calloc(engine->max_ips, sizeof(ip_statistics_t));
    if (!engine->ip_stats) {
        fprintf(stderr, "[Rule Engine] Failed to allocate IP statistics table\n");
        free(engine);
        return NULL;
    }
    engine->ip_stats_count = 0;
    
    // Allocate detections array
    engine->max_detections = 1000;
    engine->detections = calloc(engine->max_detections, sizeof(attack_detection_t));
    if (!engine->detections) {
        fprintf(stderr, "[Rule Engine] Failed to allocate detections array\n");
        free(engine->ip_stats);
        free(engine);
        return NULL;
    }
    engine->detection_count = 0;
    
    // Initialize statistics
    memset(engine->attacks_by_type, 0, sizeof(engine->attacks_by_type));
    engine->total_packets_analyzed = 0;
    engine->total_attacks_detected = 0;
    
    printf("[Rule Engine] Initialized successfully\n");
    printf("[Rule Engine] Max IPs: %u, Max Detections: %u\n", 
           engine->max_ips, engine->max_detections);
    
    return engine;
}

void rule_engine_destroy(rule_engine_t *engine) {
    if (!engine) return;
    
    if (engine->ip_stats) free(engine->ip_stats);
    if (engine->detections) free(engine->detections);
    
    free(engine);
    printf("[Rule Engine] Destroyed\n");
}

void rule_engine_set_default_thresholds(rule_engine_t *engine) {
    detection_thresholds_t *t = &engine->thresholds;
    
    // SYN Flood Detection
    t->syn_flood_threshold = 100;          // 100 SYN/sec
    t->syn_flood_ratio = 3.0;              // SYN:ACK ratio > 3:1
    t->syn_flood_time_window = 10;         // 10 seconds
    
    // UDP Flood Detection
    t->udp_flood_threshold = 200;          // 200 UDP packets/sec
    t->udp_flood_time_window = 10;         // 10 seconds
    t->udp_flood_packet_count = 1000;      // Minimum 1000 packets
    
    // HTTP Flood Detection
    t->http_flood_threshold = 50;          // 50 HTTP requests/sec
    t->http_flood_time_window = 10;        // 10 seconds
    
    // Ping of Death Detection
    t->pod_packet_size = 65500;            // ICMP packets > 65500 bytes
    
    // ARP Spoofing Detection
    t->arp_spoofing_mac_changes = 3;       // 3+ MAC addresses for same IP
    t->arp_spoofing_time_window = 60;      // 60 seconds
    
    // RUDY (Slow POST) Detection
    t->rudy_avg_body_rate = 10.0;          // < 10 bytes/sec
    t->rudy_min_packets = 10;              // Minimum 10 packets
    t->rudy_time_window = 30;              // 30 seconds
    
    // Port Scan Detection
    t->port_scan_unique_ports = 20;        // 20+ unique ports
    t->port_scan_time_window = 60;         // 60 seconds
    t->port_scan_connection_ratio = 0.7;   // 70%+ failed connections
    
    // TCP Connect Scan Detection
    t->tcp_connect_scan_ports = 15;        // 15+ unique ports
    t->tcp_connect_scan_completion = 0.8;  // 80%+ completed connections
    
    // ICMP Flood Detection
    t->icmp_flood_threshold = 100;         // 100 ICMP packets/sec
    t->icmp_flood_time_window = 10;        // 10 seconds
    
    printf("[Rule Engine] Default thresholds loaded\n");
}

/* ========== IP Statistics Management ========== */

ip_statistics_t* get_or_create_ip_stats(rule_engine_t *engine, uint32_t ip_address) {
    // Search for existing IP stats
    for (uint32_t i = 0; i < engine->ip_stats_count; i++) {
        if (engine->ip_stats[i].ip_address == ip_address) {
            return &engine->ip_stats[i];
        }
    }
    
    // Create new IP stats entry
    if (engine->ip_stats_count >= engine->max_ips) {
        return NULL;  // Table full
    }
    
    ip_statistics_t *new_stats = &engine->ip_stats[engine->ip_stats_count];
    memset(new_stats, 0, sizeof(ip_statistics_t));
    new_stats->ip_address = ip_address;
    engine->ip_stats_count++;
    
    return new_stats;
}

void update_ip_statistics(rule_engine_t *engine, const parsed_packet_t *packet) {
    // Update source IP statistics
    ip_statistics_t *src_stats = get_or_create_ip_stats(engine, packet->layer3.src_ip);
    if (src_stats) {
        // Update timing
        if (src_stats->first_seen.tv_sec == 0) {
            src_stats->first_seen = packet->timestamp;
        }
        src_stats->last_seen = packet->timestamp;
        
        // Update protocol-specific counters
        if (packet->layer3.protocol == IPPROTO_TCP) {
            if (packet->layer4.tcp_flags & 0x02) {  // SYN
                src_stats->total_syn_packets++;
                if (!(packet->layer4.tcp_flags & 0x10)) {  // SYN without ACK
                    // Track connection attempt
                }
            }
            if ((packet->layer4.tcp_flags & 0x12) == 0x12) {  // SYN-ACK
                src_stats->total_syn_ack_packets++;
            }
            if (packet->layer4.tcp_flags & 0x10) {  // ACK
                src_stats->total_ack_packets++;
            }
            
            // Track unique destination ports
            int port_exists = 0;
            for (uint32_t i = 0; i < src_stats->unique_dst_port_count; i++) {
                if (src_stats->unique_dst_ports[i] == packet->layer4.dst_port) {
                    port_exists = 1;
                    break;
                }
            }
            if (!port_exists && src_stats->unique_dst_port_count < 1024) {
                src_stats->unique_dst_ports[src_stats->unique_dst_port_count++] = 
                    packet->layer4.dst_port;
            }
        } else if (packet->layer3.protocol == IPPROTO_UDP) {
            src_stats->total_udp_packets++;
        } else if (packet->layer3.protocol == IPPROTO_ICMP) {
            src_stats->total_icmp_packets++;
        }
        
        // HTTP detection (port 80 or 8080)
        if (packet->layer4.dst_port == 80 || packet->layer4.dst_port == 8080) {
            src_stats->total_http_requests++;
        }
        
        // Track MAC address for ARP spoofing detection
        int mac_exists = 0;
        for (uint32_t i = 0; i < src_stats->mac_address_count; i++) {
            if (memcmp(src_stats->mac_addresses[i], packet->layer2.src_mac, 6) == 0) {
                mac_exists = 1;
                break;
            }
        }
        if (!mac_exists && src_stats->mac_address_count < 10) {
            memcpy(src_stats->mac_addresses[src_stats->mac_address_count++], 
                   packet->layer2.src_mac, 6);
        }
    }
}

/* ========== Detection Recording ========== */

void add_detection(rule_engine_t *engine, const attack_detection_t *detection) {
    if (engine->detection_count >= engine->max_detections) {
        fprintf(stderr, "[Rule Engine] Maximum detections reached\n");
        return;
    }
    
    memcpy(&engine->detections[engine->detection_count], detection, 
           sizeof(attack_detection_t));
    engine->detection_count++;
    engine->total_attacks_detected++;
    engine->attacks_by_type[detection->attack_type]++;
}

/* ========== Utility Functions ========== */

const char* attack_type_to_string(attack_type_t type) {
    switch(type) {
        case ATTACK_SYN_FLOOD: return "SYN Flood";
        case ATTACK_UDP_FLOOD: return "UDP Flood";
        case ATTACK_HTTP_FLOOD: return "HTTP Flood";
        case ATTACK_PING_OF_DEATH: return "Ping of Death";
        case ATTACK_ARP_SPOOFING: return "ARP Spoofing";
        case ATTACK_RUDY: return "RUDY (Slow POST)";
        case ATTACK_TCP_SYN_SCAN: return "TCP SYN Scan";
        case ATTACK_TCP_CONNECT_SCAN: return "TCP Connect Scan";
        case ATTACK_UDP_SCAN: return "UDP Scan";
        case ATTACK_PORT_SCAN_GENERIC: return "Port Scan";
        case ATTACK_ICMP_FLOOD: return "ICMP Flood";
        case ATTACK_MULTIPLE: return "Multiple Attacks";
        default: return "Unknown Attack";
    }
}

const char* severity_to_string(attack_severity_t severity) {
    switch(severity) {
        case SEVERITY_INFO: return "INFO";
        case SEVERITY_LOW: return "LOW";
        case SEVERITY_MEDIUM: return "MEDIUM";
        case SEVERITY_HIGH: return "HIGH";
        case SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char* get_severity_color(attack_severity_t severity) {
    switch(severity) {
        case SEVERITY_INFO: return "\033[0;37m";      // White
        case SEVERITY_LOW: return "\033[0;32m";       // Green
        case SEVERITY_MEDIUM: return "\033[0;33m";    // Yellow
        case SEVERITY_HIGH: return "\033[0;31m";      // Red
        case SEVERITY_CRITICAL: return "\033[1;31m";  // Bold Red
        default: return "\033[0m";                    // Reset
    }
}

/* ========== Per-Packet Analysis ========== */

void rule_engine_analyze_packet(rule_engine_t *engine, const parsed_packet_t *packet) {
    engine->total_packets_analyzed++;
    
    // Update IP statistics
    update_ip_statistics(engine, packet);
    
    // Update timing
    if (engine->analysis_start_time.tv_sec == 0) {
        engine->analysis_start_time = packet->timestamp;
    }
    engine->analysis_end_time = packet->timestamp;
}

/* ========== Batch Flow Analysis ========== */

void rule_engine_analyze_all_flows(rule_engine_t *engine, const dpi_engine_t *dpi_engine) {
    printf("\n[Rule Engine] Analyzing %u flows for attacks...\n", dpi_engine->flow_count);
    
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        rule_engine_analyze_flow(engine, &dpi_engine->flows[i]);
    }
    
    printf("[Rule Engine] Analysis complete. Detected %lu attacks.\n", 
           engine->total_attacks_detected);
}

void rule_engine_analyze_flow(rule_engine_t *engine, const flow_stats_t *flow) {
    attack_detection_t detection;
    int attack_found = 0;
    
    printf("\n┌─────────────────────────────────────────────────────────┐\n");
    printf("│  RUNNING ATTACK DETECTION CHECKS                        │\n");
    printf("└─────────────────────────────────────────────────────────┘\n");
    
    // Run all detection algorithms with status reporting
    printf("  [1/9] Checking for SYN Flood attack... ");
    fflush(stdout);
    if (detect_syn_flood(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("  [2/9] Checking for UDP Flood attack... ");
    fflush(stdout);
    if (detect_udp_flood(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("  [3/9] Checking for ICMP Flood attack... ");
    fflush(stdout);
    if (detect_icmp_flood(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("  [4/9] Checking for HTTP Flood attack... ");
    fflush(stdout);
    if (detect_http_flood(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("  [5/9] Checking for Ping of Death attack... ");
    fflush(stdout);
    if (detect_ping_of_death(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("  [6/9] Checking for TCP SYN Scan attack... ");
    fflush(stdout);
    if (detect_tcp_syn_scan(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("  [7/9] Checking for TCP Connect Scan attack... ");
    fflush(stdout);
    if (detect_tcp_connect_scan(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("  [8/9] Checking for UDP Scan attack... ");
    fflush(stdout);
    if (detect_udp_scan(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("  [9/9] Checking for RUDY (Slow POST) attack... ");
    fflush(stdout);
    if (detect_rudy_attack(engine, flow, &detection)) {
        printf("\033[1;31m⚠ DETECTED\033[0m\n");
        add_detection(engine, &detection);
        attack_found = 1;
    } else {
        printf("\033[0;32m✓ Not Found\033[0m\n");
    }
    
    printf("\n");
    if (attack_found) {
        printf("  \033[1;31m⚠ SECURITY ALERT: Attack(s) detected in flow!\033[0m\n");
    } else {
        printf("  \033[1;32m✓ FLOW CLEAN: No attacks detected\033[0m\n");
    }
    printf("\n");
}

/* This file continues in rule_engine_attacks.c for specific attack detection */
