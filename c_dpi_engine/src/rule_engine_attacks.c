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

/* ========== Aggregate SYN Flood Detection ========== */
// Detects distributed SYN flood: many flows with few SYN packets each to same target
void detect_aggregate_syn_flood(rule_engine_t *engine, const dpi_engine_t *dpi_engine) {
    // Track SYN counts per destination IP
    typedef struct {
        uint32_t dst_ip;
        uint32_t total_syn_count;
        uint32_t flow_count;
        uint32_t syn_only_flows;  // Flows with SYN but no ACK
        uint64_t total_bytes;     // Total bytes in all flows
        double first_seen;
        double last_seen;
        uint32_t attacker_ips[100];  // Track up to 100 attacker IPs per target
        uint32_t attacker_count;
    } target_syn_stats_t;
    
    target_syn_stats_t targets[10000];  // Increased to track more targets
    uint32_t target_count = 0;
    
    // Aggregate SYN packets by destination IP
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        const flow_stats_t *flow = &dpi_engine->flows[i];
        
        // Skip non-TCP flows
        if (flow->protocol != IPPROTO_TCP) continue;
        
        // Skip flows with no SYN packets
        if (flow->syn_count == 0) continue;
        
        // Find or create target entry
        int found = -1;
        for (uint32_t j = 0; j < target_count; j++) {
            if (targets[j].dst_ip == flow->dst_ip) {
                found = j;
                break;
            }
        }
        
        if (found < 0) {
            if (target_count >= 10000) continue;  // Max targets reached
            found = target_count++;
            targets[found].dst_ip = flow->dst_ip;
            targets[found].total_syn_count = 0;
            targets[found].flow_count = 0;
            targets[found].syn_only_flows = 0;
            targets[found].total_bytes = 0;
            targets[found].attacker_count = 0;
            targets[found].first_seen = flow->first_seen.tv_sec + flow->first_seen.tv_usec / 1000000.0;
            targets[found].last_seen = flow->last_seen.tv_sec + flow->last_seen.tv_usec / 1000000.0;
        }
        
        targets[found].total_syn_count += flow->syn_count;
        targets[found].flow_count++;
        targets[found].total_bytes += flow->total_bytes;
        
        // Track unique attacker IPs (up to 100 per target)
        if (targets[found].attacker_count < 100) {
            int already_tracked = 0;
            for (uint32_t k = 0; k < targets[found].attacker_count; k++) {
                if (targets[found].attacker_ips[k] == flow->src_ip) {
                    already_tracked = 1;
                    break;
                }
            }
            if (!already_tracked) {
                targets[found].attacker_ips[targets[found].attacker_count++] = flow->src_ip;
            }
        }
        
        // Update time window
        double flow_first = flow->first_seen.tv_sec + flow->first_seen.tv_usec / 1000000.0;
        double flow_last = flow->last_seen.tv_sec + flow->last_seen.tv_usec / 1000000.0;
        if (flow_first < targets[found].first_seen) targets[found].first_seen = flow_first;
        if (flow_last > targets[found].last_seen) targets[found].last_seen = flow_last;
        
        // Count SYN-only flows (no ACK received = incomplete handshake)
        if (flow->ack_count == 0 && flow->syn_count > 0) {
            targets[found].syn_only_flows++;
        }
    }
    
    // Check if this is a network scan (many targets, few SYNs each from same attacker)
    if (target_count > 100) {
        // Count common attacker IPs across targets
        uint32_t common_attackers[10];
        uint32_t common_attacker_count = 0;
        
        // Find most common attackers
        for (uint32_t i = 0; i < target_count && i < 100; i++) {
            for (uint32_t j = 0; j < targets[i].attacker_count && j < 5; j++) {
                uint32_t attacker_ip = targets[i].attacker_ips[j];
                int already_counted = 0;
                for (uint32_t k = 0; k < common_attacker_count; k++) {
                    if (common_attackers[k] == attacker_ip) {
                        already_counted = 1;
                        break;
                    }
                }
                if (!already_counted && common_attacker_count < 10) {
                    common_attackers[common_attacker_count++] = attacker_ip;
                }
            }
        }
        
        // If 1-10 common attackers hitting 100+ targets, it's a scan - create ONE detection
        if (common_attacker_count <= 10 && common_attacker_count > 0) {
            attack_detection_t detection;
            memset(&detection, 0, sizeof(attack_detection_t));
            detection.attack_type = ATTACK_TCP_CONNECT_SCAN;
            detection.severity = SEVERITY_HIGH;
            strcpy(detection.attack_name, "TCP Network Scan");
            
            // Aggregate totals
            uint32_t total_syn = 0, total_flows = 0, total_syn_only = 0;
            uint64_t total_bytes_all = 0;
            for (uint32_t i = 0; i < target_count; i++) {
                total_syn += targets[i].total_syn_count;
                total_flows += targets[i].flow_count;
                total_syn_only += targets[i].syn_only_flows;
                total_bytes_all += targets[i].total_bytes;
            }
            
            snprintf(detection.description, sizeof(detection.description),
                    "Network scan detected: %u unique targets scanned from %u source(s) with %u SYN packets across %u flows (%u incomplete)",
                    target_count, common_attacker_count, total_syn, total_flows, total_syn_only);
            
            detection.attacker_ip = common_attackers[0];
            detection.target_ip = 0;  // Multiple targets
            detection.protocol = IPPROTO_TCP;
            detection.packet_count = total_syn;
            detection.byte_count = total_bytes_all;
            detection.confidence_score = fmin(1.0, (double)target_count / 1000.0);  // 1000+ targets = 100%
            
            snprintf(detection.details, sizeof(detection.details),
                    "Scanned %u targets, Primary Scanner: %s",
                    target_count,
                    inet_ntoa((struct in_addr){.s_addr = htonl(common_attackers[0])}));
            
            add_detection(engine, &detection);
            
            // Block all scanner IPs
            for (uint32_t j = 0; j < common_attacker_count; j++) {
                block_ip(engine, common_attackers[j]);
            }
            
            printf("  \033[1;31m⚠ DETECTED: TCP Network Scan - %u targets from %s\033[0m\n",
                   target_count, inet_ntoa((struct in_addr){.s_addr = htonl(common_attackers[0])}));
            return;  // Don't report individual targets
        }
    }
    
    // Check each target for SYN flood pattern (only if not a scan)
    for (uint32_t i = 0; i < target_count; i++) {
        double duration = targets[i].last_seen - targets[i].first_seen;
        if (duration < 0.1) duration = 0.1;
        
        double syn_rate = (double)targets[i].total_syn_count / duration;
        double syn_only_ratio = (double)targets[i].syn_only_flows / (double)targets[i].flow_count;
        
        // Detection: High SYN rate OR many SYN-only flows (typical of SYN flood)
        // Lowered threshold since attack is distributed across flows
        if ((syn_rate > 20.0 && targets[i].flow_count > 10) ||  // 20+ SYN/sec across 10+ flows
            (targets[i].syn_only_flows > 15 && syn_only_ratio > 0.7)) {  // 15+ incomplete handshakes
            
            attack_detection_t detection;
            memset(&detection, 0, sizeof(attack_detection_t));
            detection.attack_type = ATTACK_SYN_FLOOD;
            detection.severity = SEVERITY_HIGH;
            strcpy(detection.attack_name, "Distributed SYN Flood Attack");
            
            snprintf(detection.description, sizeof(detection.description),
                    "Distributed SYN flood detected: %u SYN packets across %u flows from %u sources (%.2f SYN/sec, %u incomplete handshakes)",
                    targets[i].total_syn_count, targets[i].flow_count, targets[i].attacker_count, syn_rate, targets[i].syn_only_flows);
            
            detection.target_ip = targets[i].dst_ip;
            detection.attacker_ip = targets[i].attacker_count > 0 ? targets[i].attacker_ips[0] : 0;  // Primary attacker
            detection.src_port = 0;
            detection.dst_port = 0;
            detection.protocol = IPPROTO_TCP;
            
            detection.packet_count = targets[i].total_syn_count;
            detection.byte_count = targets[i].total_bytes;
            detection.packets_per_second = syn_rate;
            detection.duration_seconds = duration;
            
            // Confidence based on rate and ratio (use max to avoid 0 when one is low)
            double rate_confidence = fmin(1.0, syn_rate / 100.0);  // 100+ SYN/sec = 100%
            double ratio_confidence = fmin(1.0, syn_only_ratio / 10.0);  // 10:1 ratio = 100%
            detection.confidence_score = fmax(rate_confidence, ratio_confidence * 0.8);
            
            // Build attacker list for details
            char attacker_list[512] = "";
            int chars_written = 0;
            for (uint32_t j = 0; j < targets[i].attacker_count && j < 10; j++) {
                chars_written += snprintf(attacker_list + chars_written, sizeof(attacker_list) - chars_written,
                                         "%s%s", j > 0 ? ", " : "",
                                         inet_ntoa((struct in_addr){.s_addr = htonl(targets[i].attacker_ips[j])}));
            }
            if (targets[i].attacker_count > 10) {
                snprintf(attacker_list + chars_written, sizeof(attacker_list) - chars_written,
                        ", +%u more", targets[i].attacker_count - 10);
            }
            
            snprintf(detection.details, sizeof(detection.details),
                    "Target: %s, Total Flows: %u, SYN-only Flows: %u, Duration: %.2fs, Attackers: %s",
                    inet_ntoa((struct in_addr){.s_addr = htonl(targets[i].dst_ip)}),
                    targets[i].flow_count, targets[i].syn_only_flows, duration, attacker_list);
            
            add_detection(engine, &detection);
            
            // Block all attacker IPs
            for (uint32_t j = 0; j < targets[i].attacker_count; j++) {
                block_ip(engine, targets[i].attacker_ips[j]);
            }
            
            printf("  \033[1;31m⚠ DETECTED: Distributed SYN Flood to %s (%u flows, %.2f SYN/sec)\033[0m\n",
                   inet_ntoa((struct in_addr){.s_addr = htonl(targets[i].dst_ip)}),
                   targets[i].flow_count, syn_rate);
        }
    }
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
