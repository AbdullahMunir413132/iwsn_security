/*
 * Rule Engine - Attack Detection Implementations
 * Specific detection algorithms for each attack type
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include "rule_engine.h"

/* ========== SYN Flood Detection ========== */

int detect_syn_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                     attack_detection_t *detection) {
    
    // Only check TCP flows
    if (flow->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // Calculate duration
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                     (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
    
    if (duration < 0.1) duration = 0.1;  // Avoid division by zero
    
    // Calculate SYN rate
    double syn_rate = (double)flow->syn_count / duration;
    
    // Calculate SYN to ACK ratio
    double syn_ack_ratio = 0.0;
    if (flow->ack_count > 0) {
        syn_ack_ratio = (double)flow->syn_count / (double)flow->ack_count;
    } else if (flow->syn_count > 0) {
        syn_ack_ratio = 999.0;  // No ACKs received at all
    }
    
    // Detection logic: High SYN rate + High SYN:ACK ratio
    if (syn_rate > engine->thresholds.syn_flood_threshold &&
        syn_ack_ratio > engine->thresholds.syn_flood_ratio) {
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_SYN_FLOOD;
        detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "SYN Flood Attack");
        
        snprintf(detection->description, sizeof(detection->description),
                "High rate of SYN packets detected (%.2f SYN/sec, SYN:ACK ratio %.2f:1)",
                syn_rate, syn_ack_ratio);
        
        detection->attacker_ip = flow->src_ip;
        detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port;
        detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol;
        
        detection->packet_count = flow->syn_count;
        detection->byte_count = flow->total_bytes;
        detection->packets_per_second = syn_rate;
        detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen;
        
        // Confidence score based on ratio and rate
        detection->confidence_score = fmin(1.0, 
            (syn_rate / (engine->thresholds.syn_flood_threshold * 2.0)) * 
            (syn_ack_ratio / (engine->thresholds.syn_flood_ratio * 2.0)));
        
        snprintf(detection->details, sizeof(detection->details),
                "SYN Count: %u, ACK Count: %u, Connection Attempts: %u, Duration: %.2fs",
                flow->syn_count, flow->ack_count, flow->connection_attempts, duration);
        
        return 1;
    }
    
    return 0;
}

/* ========== UDP Flood Detection ========== */

int detect_udp_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                     attack_detection_t *detection) {
    
    // Only check UDP flows
    if (flow->protocol != IPPROTO_UDP) {
        return 0;
    }
    
    // Calculate duration
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                     (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
    
    if (duration < 0.1) duration = 0.1;
    
    // Calculate UDP packet rate
    double udp_rate = (double)flow->total_packets / duration;
    
    // Detection logic: High UDP rate + Minimum packet count
    if (udp_rate > engine->thresholds.udp_flood_threshold &&
        flow->total_packets > engine->thresholds.udp_flood_packet_count) {
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_UDP_FLOOD;
        detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "UDP Flood Attack");
        
        snprintf(detection->description, sizeof(detection->description),
                "High rate of UDP packets detected (%.2f packets/sec)",
                udp_rate);
        
        detection->attacker_ip = flow->src_ip;
        detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port;
        detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol;
        
        detection->packet_count = flow->total_packets;
        detection->byte_count = flow->total_bytes;
        detection->packets_per_second = udp_rate;
        detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen;
        
        detection->confidence_score = fmin(1.0, 
            udp_rate / (engine->thresholds.udp_flood_threshold * 2.0));
        
        snprintf(detection->details, sizeof(detection->details),
                "UDP Packets: %lu, Bytes: %lu, Rate: %.2f pkt/s, Duration: %.2fs",
                flow->total_packets, flow->total_bytes, udp_rate, duration);
        
        return 1;
    }
    
    return 0;
}

/* ========== HTTP Flood Detection ========== */

int detect_http_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                      attack_detection_t *detection) {
    
    // Check if this is HTTP traffic (port 80, 8080, or detected as HTTP)
    int is_http = (flow->dst_port == 80 || flow->dst_port == 8080 ||
                   strstr(flow->protocol_name, "HTTP") != NULL);
    
    if (!is_http || flow->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // Calculate duration
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                     (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
    
    if (duration < 0.1) duration = 0.1;
    
    // Estimate HTTP request rate (each packet with PSH flag is likely a request)
    double request_rate = (double)flow->total_packets / duration;
    
    // Detection logic: High HTTP request rate
    if (request_rate > engine->thresholds.http_flood_threshold) {
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_HTTP_FLOOD;
        detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "HTTP Flood Attack");
        
        snprintf(detection->description, sizeof(detection->description),
                "High rate of HTTP requests detected (%.2f requests/sec)",
                request_rate);
        
        detection->attacker_ip = flow->src_ip;
        detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port;
        detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol;
        
        detection->packet_count = flow->total_packets;
        detection->byte_count = flow->total_bytes;
        detection->packets_per_second = request_rate;
        detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen;
        
        detection->confidence_score = fmin(1.0, 
            request_rate / (engine->thresholds.http_flood_threshold * 2.0));
        
        snprintf(detection->details, sizeof(detection->details),
                "HTTP Packets: %lu, Target Port: %u, Rate: %.2f req/s, Duration: %.2fs",
                flow->total_packets, flow->dst_port, request_rate, duration);
        
        return 1;
    }
    
    return 0;
}

/* ========== Ping of Death Detection ========== */

int detect_ping_of_death(rule_engine_t *engine, const flow_stats_t *flow, 
                         attack_detection_t *detection) {
    
    // Only check ICMP traffic
    if (flow->protocol != IPPROTO_ICMP) {
        return 0;
    }
    
    // Check for oversized ICMP packets
    if (flow->max_packet_size > engine->thresholds.pod_packet_size) {
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_PING_OF_DEATH;
        detection->severity = SEVERITY_CRITICAL;
        strcpy(detection->attack_name, "Ping of Death");
        
        snprintf(detection->description, sizeof(detection->description),
                "Oversized ICMP packet detected (%u bytes, threshold: %u bytes)",
                flow->max_packet_size, engine->thresholds.pod_packet_size);
        
        detection->attacker_ip = flow->src_ip;
        detection->target_ip = flow->dst_ip;
        detection->src_port = 0;
        detection->dst_port = 0;
        detection->protocol = flow->protocol;
        
        detection->packet_count = flow->total_packets;
        detection->byte_count = flow->total_bytes;
        detection->duration_seconds = 0;
        detection->detection_time = flow->last_seen;
        
        detection->confidence_score = 1.0;  // High confidence for PoD
        
        snprintf(detection->details, sizeof(detection->details),
                "Max ICMP Size: %u bytes (Normal max: 65535), Min: %u, Avg: %lu",
                flow->max_packet_size, flow->min_packet_size,
                flow->total_packets > 0 ? flow->total_packet_size / flow->total_packets : 0);
        
        return 1;
    }
    
    return 0;
}

/* ========== ARP Spoofing Detection ========== */

int detect_arp_spoofing(rule_engine_t *engine, const flow_stats_t *flow, 
                        attack_detection_t *detection) {
    
    // Look for IP statistics with multiple MAC addresses
    ip_statistics_t *ip_stats = NULL;
    for (uint32_t i = 0; i < engine->ip_stats_count; i++) {
        if (engine->ip_stats[i].ip_address == flow->src_ip) {
            ip_stats = &engine->ip_stats[i];
            break;
        }
    }
    
    if (!ip_stats) {
        return 0;
    }
    
    // Check if multiple MAC addresses are used for this IP
    if (ip_stats->mac_address_count >= engine->thresholds.arp_spoofing_mac_changes) {
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_ARP_SPOOFING;
        detection->severity = SEVERITY_CRITICAL;
        strcpy(detection->attack_name, "ARP Spoofing");
        
        snprintf(detection->description, sizeof(detection->description),
                "Multiple MAC addresses detected for single IP (%u MACs)",
                ip_stats->mac_address_count);
        
        detection->attacker_ip = flow->src_ip;
        detection->target_ip = flow->dst_ip;
        detection->protocol = 0;  // Layer 2 attack
        detection->detection_time = flow->last_seen;
        detection->confidence_score = 0.9;
        
        // List MAC addresses in details
        char mac_list[256] = "";
        for (uint32_t i = 0; i < ip_stats->mac_address_count && i < 5; i++) {
            char mac_str[32];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x ",
                    ip_stats->mac_addresses[i][0], ip_stats->mac_addresses[i][1],
                    ip_stats->mac_addresses[i][2], ip_stats->mac_addresses[i][3],
                    ip_stats->mac_addresses[i][4], ip_stats->mac_addresses[i][5]);
            strcat(mac_list, mac_str);
        }
        
        snprintf(detection->details, sizeof(detection->details),
                "Suspicious IP has %u different MAC addresses: %s",
                ip_stats->mac_address_count, mac_list);
        
        return 1;
    }
    
    return 0;
}

/* ========== RUDY (Slow POST) Attack Detection ========== */

int detect_rudy_attack(rule_engine_t *engine, const flow_stats_t *flow, 
                       attack_detection_t *detection) {
    
    // Check if this is HTTP POST traffic
    int is_http = (flow->dst_port == 80 || flow->dst_port == 8080 ||
                   strstr(flow->protocol_name, "HTTP") != NULL);
    
    if (!is_http || flow->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // Need minimum packets to analyze
    if (flow->total_packets < engine->thresholds.rudy_min_packets) {
        return 0;
    }
    
    // Calculate duration
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                     (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
    
    if (duration < 1.0) {
        return 0;  // Need longer duration to detect slow attacks
    }
    
    // Calculate average data rate
    double avg_rate = (double)flow->total_bytes / duration;
    
    // Detection: Very slow data transmission rate (RUDY keeps connection alive with minimal data)
    if (avg_rate < engine->thresholds.rudy_avg_body_rate && 
        duration > engine->thresholds.rudy_time_window) {
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_RUDY;
        detection->severity = SEVERITY_MEDIUM;
        strcpy(detection->attack_name, "RUDY (R-U-Dead-Yet) Slow POST Attack");
        
        snprintf(detection->description, sizeof(detection->description),
                "Slow HTTP POST detected (%.2f bytes/sec over %.2f seconds)",
                avg_rate, duration);
        
        detection->attacker_ip = flow->src_ip;
        detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port;
        detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol;
        
        detection->packet_count = flow->total_packets;
        detection->byte_count = flow->total_bytes;
        detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen;
        
        detection->confidence_score = 0.7;
        
        snprintf(detection->details, sizeof(detection->details),
                "HTTP connection kept alive with minimal data. Packets: %lu, "
                "Avg Rate: %.2f bytes/sec, Duration: %.2fs",
                flow->total_packets, avg_rate, duration);
        
        return 1;
    }
    
    return 0;
}

/* ========== TCP SYN Scan Detection ========== */

int detect_tcp_syn_scan(rule_engine_t *engine, const flow_stats_t *flow, 
                        attack_detection_t *detection) {
    
    // Only check TCP flows
    if (flow->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // Look for flows with many SYNs but few completed connections
    // SYN scan: SYN sent, if SYN-ACK received, RST sent (no connection completion)
    
    // High SYN count, low ACK completion, presence of RST
    if (flow->syn_count > 5 && flow->rst_count > 0 && 
        flow->ack_count < (flow->syn_count * 0.3)) {
        
        // Also check if multiple ports are being scanned
        if (flow->unique_dst_port_count >= engine->thresholds.tcp_connect_scan_ports) {
            
            memset(detection, 0, sizeof(attack_detection_t));
            detection->attack_type = ATTACK_TCP_SYN_SCAN;
            detection->severity = SEVERITY_MEDIUM;
            strcpy(detection->attack_name, "TCP SYN Scan (Port Scanning)");
            
            snprintf(detection->description, sizeof(detection->description),
                    "TCP SYN scan detected targeting %u ports", 
                    flow->unique_dst_port_count);
            
            detection->attacker_ip = flow->src_ip;
            detection->target_ip = flow->dst_ip;
            detection->protocol = flow->protocol;
            
            detection->packet_count = flow->total_packets;
            detection->duration_seconds = 
                (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
            detection->detection_time = flow->last_seen;
            
            detection->confidence_score = fmin(1.0, 
                (double)flow->unique_dst_port_count / 50.0);
            
            snprintf(detection->details, sizeof(detection->details),
                    "SYN: %u, RST: %u, ACK: %u, Unique Ports: %u. "
                    "Pattern matches stealthy SYN scan.",
                    flow->syn_count, flow->rst_count, flow->ack_count, 
                    flow->unique_dst_port_count);
            
            return 1;
        }
    }
    
    return 0;
}

/* ========== TCP Connect Scan Detection ========== */

int detect_tcp_connect_scan(rule_engine_t *engine, const flow_stats_t *flow, 
                            attack_detection_t *detection) {
    
    // Only check TCP flows
    if (flow->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // TCP Connect scan: Full 3-way handshake completed, then immediate close
    // Look for: Multiple destination ports + completed connections + quick termination
    
    if (flow->unique_dst_port_count >= engine->thresholds.tcp_connect_scan_ports) {
        
        // Calculate connection completion ratio
        double completion_ratio = 0.0;
        if (flow->syn_count > 0) {
            completion_ratio = (double)flow->ack_count / (double)flow->syn_count;
        }
        
        // High completion ratio suggests connect scan (vs SYN scan)
        if (completion_ratio > engine->thresholds.tcp_connect_scan_completion) {
            
            memset(detection, 0, sizeof(attack_detection_t));
            detection->attack_type = ATTACK_TCP_CONNECT_SCAN;
            detection->severity = SEVERITY_MEDIUM;
            strcpy(detection->attack_name, "TCP Connect Scan (Port Scanning)");
            
            snprintf(detection->description, sizeof(detection->description),
                    "TCP Connect scan detected targeting %u ports", 
                    flow->unique_dst_port_count);
            
            detection->attacker_ip = flow->src_ip;
            detection->target_ip = flow->dst_ip;
            detection->protocol = flow->protocol;
            
            detection->packet_count = flow->total_packets;
            detection->duration_seconds = 
                (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
            detection->detection_time = flow->last_seen;
            
            detection->confidence_score = fmin(1.0, 
                (double)flow->unique_dst_port_count / 50.0);
            
            snprintf(detection->details, sizeof(detection->details),
                    "SYN: %u, ACK: %u, FIN: %u, Unique Ports: %u, "
                    "Completion Ratio: %.2f. Full connections established.",
                    flow->syn_count, flow->ack_count, flow->fin_count,
                    flow->unique_dst_port_count, completion_ratio);
            
            return 1;
        }
    }
    
    return 0;
}

/* ========== UDP Scan Detection ========== */

int detect_udp_scan(rule_engine_t *engine, const flow_stats_t *flow, 
                    attack_detection_t *detection) {
    
    // Only check UDP flows
    if (flow->protocol != IPPROTO_UDP) {
        return 0;
    }
    
    // UDP scan: Multiple destination ports accessed with minimal data
    if (flow->unique_dst_port_count >= engine->thresholds.port_scan_unique_ports) {
        
        // Calculate average packet size
        uint64_t avg_packet_size = 0;
        if (flow->total_packets > 0) {
            avg_packet_size = flow->total_packet_size / flow->total_packets;
        }
        
        // Small packets suggest scanning (not legitimate data transfer)
        if (avg_packet_size < 100) {
            
            memset(detection, 0, sizeof(attack_detection_t));
            detection->attack_type = ATTACK_UDP_SCAN;
            detection->severity = SEVERITY_MEDIUM;
            strcpy(detection->attack_name, "UDP Scan (Port Scanning)");
            
            snprintf(detection->description, sizeof(detection->description),
                    "UDP scan detected targeting %u ports", 
                    flow->unique_dst_port_count);
            
            detection->attacker_ip = flow->src_ip;
            detection->target_ip = flow->dst_ip;
            detection->protocol = flow->protocol;
            
            detection->packet_count = flow->total_packets;
            detection->duration_seconds = 
                (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
            detection->detection_time = flow->last_seen;
            
            detection->confidence_score = fmin(1.0, 
                (double)flow->unique_dst_port_count / 100.0);
            
            snprintf(detection->details, sizeof(detection->details),
                    "UDP Packets: %lu, Unique Ports: %u, Avg Packet Size: %lu bytes. "
                    "Small packets to many ports suggest scanning.",
                    flow->total_packets, flow->unique_dst_port_count, avg_packet_size);
            
            return 1;
        }
    }
    
    return 0;
}

/* ========== ICMP Flood Detection ========== */

int detect_icmp_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                      attack_detection_t *detection) {
    
    // Only check ICMP traffic
    if (flow->protocol != IPPROTO_ICMP) {
        return 0;
    }
    
    // Calculate duration
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                     (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
    
    if (duration < 0.1) duration = 0.1;
    
    // Calculate ICMP packet rate
    double icmp_rate = (double)flow->total_packets / duration;
    
    // Detection logic: High ICMP rate
    if (icmp_rate > engine->thresholds.icmp_flood_threshold) {
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_ICMP_FLOOD;
        detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "ICMP Flood Attack");
        
        snprintf(detection->description, sizeof(detection->description),
                "High rate of ICMP packets detected (%.2f packets/sec)",
                icmp_rate);
        
        detection->attacker_ip = flow->src_ip;
        detection->target_ip = flow->dst_ip;
        detection->protocol = flow->protocol;
        
        detection->packet_count = flow->total_packets;
        detection->byte_count = flow->total_bytes;
        detection->packets_per_second = icmp_rate;
        detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen;
        
        detection->confidence_score = fmin(1.0, 
            icmp_rate / (engine->thresholds.icmp_flood_threshold * 2.0));
        
        snprintf(detection->details, sizeof(detection->details),
                "ICMP Packets: %lu, Bytes: %lu, Rate: %.2f pkt/s, Duration: %.2fs",
                flow->total_packets, flow->total_bytes, icmp_rate, duration);
        
        return 1;
    }
    
    return 0;
}
