/*
 * Rule Engine - Main Implementation
 * Core functions for RFC-compliant attack detection and analysis
 *
 * Standards References:
 *   RFC 4987 - TCP SYN Flooding Attacks
 *   RFC 4732 - Internet DoS Considerations
 *   RFC 6274 - Security Assessment of IPv4
 *   RFC 2827 - Network Ingress Filtering (BCP 38)
 *   NIST SP 800-94 - Guide to IDPS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "rule_engine.h"

/* ========== Engine Initialization ========== */

rule_engine_t* rule_engine_init(void) {
    rule_engine_t *engine = calloc(1, sizeof(rule_engine_t));
    if (!engine) {
        fprintf(stderr, "[Rule Engine] Failed to allocate memory\n");
        return NULL;
    }
    
    /* Set default thresholds */
    rule_engine_set_default_thresholds(engine);
    
    /* Allocate IP statistics table — sized for micro-IWSN (2-4 nodes + gateway) */
    engine->max_ips = 64;
    engine->ip_stats = calloc(engine->max_ips, sizeof(ip_statistics_t));
    if (!engine->ip_stats) {
        fprintf(stderr, "[Rule Engine] Failed to allocate IP statistics table\n");
        free(engine);
        return NULL;
    }
    engine->ip_stats_count = 0;
    
    /* Allocate detections array */
    engine->max_detections = 128;
    engine->detections = calloc(engine->max_detections, sizeof(attack_detection_t));
    if (!engine->detections) {
        fprintf(stderr, "[Rule Engine] Failed to allocate detections array\n");
        free(engine->ip_stats);
        free(engine);
        return NULL;
    }
    engine->detection_count = 0;
    
    /* Allocate IP blocklist */
    engine->max_blocked_ips = 64;
    engine->blocked_ips = calloc(engine->max_blocked_ips, sizeof(uint32_t));
    if (!engine->blocked_ips) {
        fprintf(stderr, "[Rule Engine] Failed to allocate IP blocklist\n");
        free(engine->detections);
        free(engine->ip_stats);
        free(engine);
        return NULL;
    }
    engine->blocked_ip_count = 0;
    engine->blocked_packet_count = 0;
    
    /* Initialize statistics */
    memset(engine->attacks_by_type, 0, sizeof(engine->attacks_by_type));
    engine->total_packets_analyzed = 0;
    engine->total_attacks_detected = 0;
    
    printf("[Rule Engine] Initialized — RFC-Compliant IDS v4.0\n");
    printf("[Rule Engine] 21 attack detection algorithms loaded\n");
    printf("[Rule Engine] Max IPs: %u, Max Detections: %u\n", 
           engine->max_ips, engine->max_detections);
    
    return engine;
}

void rule_engine_destroy(rule_engine_t *engine) {
    if (!engine) return;
    
    if (engine->blocked_ip_count > 0) {
        printf("[Rule Engine] Blocked %u attacker IPs, dropped %lu packets\n",
               engine->blocked_ip_count, engine->blocked_packet_count);
    }
    
    free(engine->blocked_ips);
    if (engine->ip_stats) free(engine->ip_stats);
    if (engine->detections) free(engine->detections);
    
    free(engine);
    printf("[Rule Engine] Destroyed\n");
}

/*
 * RFC-Aligned Default Thresholds
 * 
 * These values derive from industry best practices referenced in:
 *   RFC 4987 §3 - SYN flood characteristics
 *   RFC 4732 §2 - DoS classification framework
 *   NIST SP 800-94 §4 - Detection thresholds
 */
void rule_engine_set_default_thresholds(rule_engine_t *engine) {
    detection_thresholds_t *t = &engine->thresholds;
    
    /*
     * ── IWSN Micro-Network Thresholds (2-4 sensor nodes) ──
     *
     * Normal traffic profile: ~1-2 MQTT PUBLISH/sec per sensor, heartbeat
     * every 10s, occasional DNS/ARP. Total baseline ≈ 5-10 pkt/sec.
     * Thresholds set to 3-5x baseline to eliminate false positives
     * while still catching even low-and-slow attacks.
     */
    
    /* SYN Flood Detection (RFC 4987)
     * Normal: 0-1 SYN/sec (MQTT reconnects). Threshold at 15/sec. */
    t->syn_flood_threshold = 15;
    t->syn_flood_ratio = 3.0;              /* SYN:ACK ratio > 3:1 indicates incomplete handshakes */
    t->syn_flood_time_window = 10;
    
    /* UDP Flood Detection (RFC 4732 §2.1 - Volumetric)
     * Normal: 0-2 UDP/sec (DNS, NTP). Threshold at 30/sec. */
    t->udp_flood_threshold = 30;
    t->udp_flood_time_window = 10;
    t->udp_flood_packet_count = 100;
    
    /* HTTP Flood Detection (RFC 9110)
     * IWSN nodes don't serve HTTP; any burst is suspicious. */
    t->http_flood_threshold = 10;
    t->http_flood_time_window = 10;
    
    /* ICMP Flood Detection (RFC 792, RFC 4732)
     * Normal: 0-1 ping/sec. Threshold at 20/sec. */
    t->icmp_flood_threshold = 20;
    t->icmp_flood_time_window = 10;
    
    /* Ping of Death Detection (RFC 791 §3.2)
     * RFC 791: Maximum IP datagram size is 65535 bytes.
     * Packets exceeding this after reassembly violate protocol. */
    t->pod_packet_size = 65500;
    
    /* ARP Spoofing Detection (RFC 826, RFC 5227)
     * RFC 5227: IPv4 Address Conflict Detection.
     * Multiple MACs for same IP strongly indicates spoofing. */
    t->arp_spoofing_mac_changes = 3;
    t->arp_spoofing_time_window = 60;
    
    /* RUDY / Slow POST Detection (RFC 9110)
     * Any slow POST is suspicious on an IWSN. Lowered min packets. */
    t->rudy_avg_body_rate = 10.0;
    t->rudy_min_packets = 5;
    t->rudy_time_window = 30;
    
    /* Slowloris Detection (RFC 9110)
     * Even 2 simultaneous slow connections are abnormal on IWSN. */
    t->slowloris_header_rate = 5.0;
    t->slowloris_min_duration = 20;
    t->slowloris_min_connections = 2;
    
    /* Port Scan Detection
     * IWSN nodes expose 1-2 ports (MQTT 1883). 5+ unique ports is a scan. */
    t->port_scan_unique_ports = 5;
    t->port_scan_time_window = 30;
    t->port_scan_connection_ratio = 0.6;
    
    /* TCP Connect Scan Detection */
    t->tcp_connect_scan_ports = 5;
    t->tcp_connect_scan_completion = 0.7;
    
    /* Xmas/NULL/FIN Scan Detection (RFC 793 §3.9)
     * Any stealth scan packets to 3+ ports is suspicious on IWSN. */
    t->stealth_scan_port_threshold = 3;
    
    /* Smurf Attack Detection (BCP 38)
     * 10 ICMP echo-to-broadcast/sec is far above IWSN baseline. */
    t->smurf_icmp_threshold = 10;
    
    /* Fraggle Attack Detection (RFC 6274) */
    t->fraggle_udp_threshold = 10;
    
    /* DNS Amplification Detection (RFC 5358)
     * IWSN DNS is rare; 10 large responses/sec is clearly an attack. */
    t->dns_amp_response_size = 512;
    t->dns_amp_rate_threshold = 10;
    
    /* NTP Amplification Detection (RFC 5905, CVE-2013-5211) */
    t->ntp_amp_response_size = 468;
    t->ntp_amp_rate_threshold = 10;
    
    printf("[Rule Engine] RFC-aligned default thresholds loaded\n");
}

/* ========== IP Statistics Management ========== */

ip_statistics_t* get_or_create_ip_stats(rule_engine_t *engine, uint32_t ip_address) {
    /* Search for existing IP stats */
    for (uint32_t i = 0; i < engine->ip_stats_count; i++) {
        if (engine->ip_stats[i].ip_address == ip_address) {
            return &engine->ip_stats[i];
        }
    }
    
    /* Create new IP stats entry */
    if (engine->ip_stats_count >= engine->max_ips) {
        return NULL;  /* Table full */
    }
    
    ip_statistics_t *new_stats = &engine->ip_stats[engine->ip_stats_count];
    memset(new_stats, 0, sizeof(ip_statistics_t));
    new_stats->ip_address = ip_address;
    engine->ip_stats_count++;
    
    return new_stats;
}

void update_ip_statistics(rule_engine_t *engine, const parsed_packet_t *packet) {
    /* Update source IP statistics */
    ip_statistics_t *src_stats = get_or_create_ip_stats(engine, packet->layer3.src_ip);
    if (src_stats) {
        /* Update timing */
        if (src_stats->first_seen.tv_sec == 0) {
            src_stats->first_seen = packet->timestamp;
        }
        src_stats->last_seen = packet->timestamp;
        
        /* Update protocol-specific counters */
        if (packet->layer3.protocol == IPPROTO_TCP) {
            if (packet->layer4.tcp_flags & 0x02) {  /* SYN */
                src_stats->total_syn_packets++;
            }
            if ((packet->layer4.tcp_flags & 0x12) == 0x12) {  /* SYN-ACK */
                src_stats->total_syn_ack_packets++;
            }
            if (packet->layer4.tcp_flags & 0x10) {  /* ACK */
                src_stats->total_ack_packets++;
            }
            
            /* Track unique destination ports */
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
        
        /* HTTP detection (port 80 or 8080) */
        if (packet->layer4.dst_port == 80 || packet->layer4.dst_port == 8080) {
            src_stats->total_http_requests++;
        }
        
        /* Track MAC address for ARP spoofing detection (RFC 826, RFC 5227) */
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
    
    /* Check if similar attack already exists (same type, attacker, target) */
    for (uint32_t i = 0; i < engine->detection_count; i++) {
        attack_detection_t *existing = &engine->detections[i];
        
        /* Match: same attack type, attacker IP, and target IP */
        if (existing->attack_type == detection->attack_type &&
            existing->attacker_ip == detection->attacker_ip &&
            existing->target_ip == detection->target_ip) {
            
            /* Consolidate: update counts and take higher severity/confidence */
            existing->packet_count += detection->packet_count;
            existing->byte_count += detection->byte_count;
            
            if (detection->severity > existing->severity) {
                existing->severity = detection->severity;
            }
            if (detection->confidence_score > existing->confidence_score) {
                existing->confidence_score = detection->confidence_score;
            }
            if (detection->packets_per_second > existing->packets_per_second) {
                existing->packets_per_second = detection->packets_per_second;
            }
            
            return;
        }
    }
    
    /* No match found — add as new detection */
    memcpy(&engine->detections[engine->detection_count], detection, 
           sizeof(attack_detection_t));
    
    /* Auto-fill RFC reference if not already set */
    if (engine->detections[engine->detection_count].rfc_reference[0] == '\0') {
        strncpy(engine->detections[engine->detection_count].rfc_reference,
                get_rfc_reference(detection->attack_type),
                sizeof(engine->detections[engine->detection_count].rfc_reference) - 1);
    }
    
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
        case ATTACK_ICMP_FLOOD: return "ICMP Flood";
        case ATTACK_DNS_AMPLIFICATION: return "DNS Amplification";
        case ATTACK_NTP_AMPLIFICATION: return "NTP Amplification";
        case ATTACK_SMURF: return "Smurf Attack";
        case ATTACK_FRAGGLE: return "Fraggle Attack";
        case ATTACK_PING_OF_DEATH: return "Ping of Death";
        case ATTACK_LAND_ATTACK: return "Land Attack";
        case ATTACK_TEARDROP: return "Teardrop Attack";
        case ATTACK_IP_SPOOFING: return "IP Spoofing";
        case ATTACK_TCP_SYN_SCAN: return "TCP SYN Scan";
        case ATTACK_TCP_CONNECT_SCAN: return "TCP Connect Scan";
        case ATTACK_UDP_SCAN: return "UDP Scan";
        case ATTACK_XMAS_SCAN: return "Xmas Tree Scan";
        case ATTACK_NULL_SCAN: return "NULL Scan";
        case ATTACK_FIN_SCAN: return "FIN Scan";
        case ATTACK_PORT_SCAN_GENERIC: return "Port Scan";
        case ATTACK_RUDY: return "RUDY (Slow POST)";
        case ATTACK_SLOWLORIS: return "Slowloris";
        case ATTACK_ARP_SPOOFING: return "ARP Spoofing";
        case ATTACK_MULTIPLE: return "Multiple Attacks";
        default: return "Unknown Attack";
    }
}

/*
 * Returns the RFC/standard reference for each attack type.
 * All references verified against IETF datatracker.
 */
const char* get_rfc_reference(attack_type_t type) {
    switch(type) {
        case ATTACK_SYN_FLOOD: return "RFC 4987, RFC 793";
        case ATTACK_UDP_FLOOD: return "RFC 768, RFC 4732";
        case ATTACK_HTTP_FLOOD: return "RFC 9110, RFC 4732";
        case ATTACK_ICMP_FLOOD: return "RFC 792, RFC 4732";
        case ATTACK_DNS_AMPLIFICATION: return "RFC 5358, RFC 5625";
        case ATTACK_NTP_AMPLIFICATION: return "RFC 5905, CVE-2013-5211";
        case ATTACK_SMURF: return "RFC 2827 (BCP 38), RFC 6274";
        case ATTACK_FRAGGLE: return "RFC 768, RFC 6274";
        case ATTACK_PING_OF_DEATH: return "RFC 791 S3.2, RFC 6274 S5.3";
        case ATTACK_LAND_ATTACK: return "RFC 6274, CVE-1999-0016";
        case ATTACK_TEARDROP: return "RFC 791 S3.2, RFC 6274";
        case ATTACK_IP_SPOOFING: return "RFC 2827 (BCP 38)";
        case ATTACK_TCP_SYN_SCAN: return "RFC 793 S3.9";
        case ATTACK_TCP_CONNECT_SCAN: return "RFC 793";
        case ATTACK_UDP_SCAN: return "RFC 768";
        case ATTACK_XMAS_SCAN: return "RFC 793 S3.9";
        case ATTACK_NULL_SCAN: return "RFC 793 S3.9";
        case ATTACK_FIN_SCAN: return "RFC 793 S3.9";
        case ATTACK_RUDY: return "RFC 9110, OWASP";
        case ATTACK_SLOWLORIS: return "RFC 9110, OWASP";
        case ATTACK_ARP_SPOOFING: return "RFC 826, RFC 5227";
        default: return "N/A";
    }
}

/* ========== IP Blocking Functions ========== */

void block_ip(rule_engine_t *engine, uint32_t ip_address) {
    /* Check if already blocked */
    for (uint32_t i = 0; i < engine->blocked_ip_count; i++) {
        if (engine->blocked_ips[i] == ip_address) {
            return;
        }
    }
    
    /* Add to blocklist */
    if (engine->blocked_ip_count < engine->max_blocked_ips) {
        engine->blocked_ips[engine->blocked_ip_count++] = ip_address;
        printf("\033[1;31m[IPS] BLOCKING attacker IP: %s\033[0m\n",
               inet_ntoa((struct in_addr){.s_addr = htonl(ip_address)}));
    }
}

int is_ip_blocked(rule_engine_t *engine, uint32_t ip_address) {
    for (uint32_t i = 0; i < engine->blocked_ip_count; i++) {
        if (engine->blocked_ips[i] == ip_address) {
            return 1;
        }
    }
    return 0;
}

void check_and_block_flood_sources(rule_engine_t *engine) {
    for (uint32_t i = 0; i < engine->ip_stats_count; i++) {
        ip_statistics_t *ip = &engine->ip_stats[i];
        if (is_ip_blocked(engine, ip->ip_address)) continue;
        /* IP blocking handled by attack detection functions */
    }
    
    static uint32_t check_counter = 0;
    if (++check_counter % 10 == 0) {
        printf("[IPS Debug] Evaluated %u IPs, currently blocking %u IPs\n", 
               engine->ip_stats_count, engine->blocked_ip_count);
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
        case SEVERITY_INFO: return "\033[0;37m";
        case SEVERITY_LOW: return "\033[0;32m";
        case SEVERITY_MEDIUM: return "\033[0;33m";
        case SEVERITY_HIGH: return "\033[0;31m";
        case SEVERITY_CRITICAL: return "\033[1;31m";
        default: return "\033[0m";
    }
}

/* ========== Per-Packet Analysis ========== */

void rule_engine_analyze_packet(rule_engine_t *engine, const parsed_packet_t *packet) {
    /* Check if source IP is blocked */
    if (is_ip_blocked(engine, packet->layer3.src_ip)) {
        engine->blocked_packet_count++;
        return;
    }
    
    engine->total_packets_analyzed++;
    
    /* Update IP statistics */
    update_ip_statistics(engine, packet);
    
    /* Periodically check for flood sources */
    if (engine->total_packets_analyzed % 1000 == 0) {
        check_and_block_flood_sources(engine);
    }
    
    /* Update timing */
    if (engine->analysis_start_time.tv_sec == 0) {
        engine->analysis_start_time = packet->timestamp;
    }
    engine->analysis_end_time = packet->timestamp;
}

/* ========== Batch Flow Analysis ========== */

void rule_engine_analyze_all_flows(rule_engine_t *engine, const dpi_engine_t *dpi_engine) {
    printf("\n[Rule Engine] Analyzing %u flows for attacks...\n", dpi_engine->flow_count);
    
    /* Count total packets */
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        engine->total_packets_analyzed += dpi_engine->flows[i].total_packets;
    }
    
    /* Early detection for massive DDoS */
    if (dpi_engine->flow_count > 50000) {
        uint32_t sample_attackers[100] = {0};
        uint32_t attacker_count = 0;
        uint32_t target_ips[10] = {0};
        uint32_t target_counts[10] = {0};
        uint64_t target_bytes[10] = {0};
        uint32_t target_count = 0;
        
        uint32_t sample_limit = dpi_engine->flow_count < 5000 ? dpi_engine->flow_count : 5000;
        for (uint32_t i = 0; i < sample_limit; i++) {
            const flow_stats_t *flow = &dpi_engine->flows[i];
            
            if (attacker_count < 100) {
                int found = 0;
                for (uint32_t j = 0; j < attacker_count; j++) {
                    if (sample_attackers[j] == flow->src_ip) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    sample_attackers[attacker_count++] = flow->src_ip;
                }
            }
            
            int target_idx = -1;
            for (uint32_t j = 0; j < target_count; j++) {
                if (target_ips[j] == flow->dst_ip) {
                    target_idx = j;
                    break;
                }
            }
            if (target_idx >= 0) {
                target_counts[target_idx]++;
                target_bytes[target_idx] += flow->total_bytes;
            } else if (target_count < 10) {
                target_ips[target_count] = flow->dst_ip;
                target_counts[target_count] = 1;
                target_bytes[target_count] = flow->total_bytes;
                target_count++;
            }
        }
        
        uint32_t primary_target = 0;
        uint32_t max_attacks = 0;
        uint64_t total_attack_bytes = 0;
        for (uint32_t i = 0; i < target_count; i++) {
            if (target_counts[i] > max_attacks) {
                max_attacks = target_counts[i];
                primary_target = target_ips[i];
            }
            total_attack_bytes += target_bytes[i];
        }
        
        attack_detection_t detection;
        memset(&detection, 0, sizeof(attack_detection_t));
        detection.attack_type = ATTACK_SYN_FLOOD;
        detection.severity = SEVERITY_CRITICAL;
        strcpy(detection.attack_name, "Massive DDoS Flood Attack");
        strncpy(detection.rfc_reference, "RFC 4987, RFC 4732", sizeof(detection.rfc_reference) - 1);
        
        snprintf(detection.description, sizeof(detection.description),
                "Massive DDoS: %u flows from %u+ sources (RFC 4732 volumetric attack)",
                dpi_engine->flow_count, attacker_count);
        
        char attacker_list[512] = "";
        int chars_written = 0;
        for (uint32_t i = 0; i < attacker_count && i < 10; i++) {
            chars_written += snprintf(attacker_list + chars_written,
                sizeof(attacker_list) - chars_written, "%s%s", i > 0 ? ", " : "",
                inet_ntoa((struct in_addr){.s_addr = htonl(sample_attackers[i])}));
        }
        if (attacker_count > 10) {
            snprintf(attacker_list + chars_written,
                sizeof(attacker_list) - chars_written, ", +%u more", attacker_count - 10);
        }
        
        snprintf(detection.details, sizeof(detection.details),
                "Total flows: %u, Total packets: %lu, Primary target: %s, "
                "%u unique targets, Attackers: %s",
                dpi_engine->flow_count, dpi_engine->total_packets,
                inet_ntoa((struct in_addr){.s_addr = htonl(primary_target)}),
                target_count, attacker_list);
        
        detection.packet_count = dpi_engine->total_packets;
        detection.byte_count = total_attack_bytes;
        detection.attacker_ip = attacker_count > 0 ? sample_attackers[0] : 0;
        detection.target_ip = primary_target;
        detection.confidence_score = fmin(1.0, (double)dpi_engine->flow_count / 100000.0);
        
        add_detection(engine, &detection);
        
        printf("\n\033[1;31m═══════════════════════════════════════════════════════════════\033[0m\n");
        printf("\033[1;31m⚠️  CRITICAL: MASSIVE DDoS DETECTED — %u flows!\033[0m\n", dpi_engine->flow_count);
        printf("\033[1;31m   Primary Target: %s (%u attacks)\033[0m\n",
               inet_ntoa((struct in_addr){.s_addr = htonl(primary_target)}), max_attacks);
        printf("\033[1;31m   Attackers: %u+ sources detected\033[0m\n", attacker_count);
        printf("\033[1;31m═══════════════════════════════════════════════════════════════\033[0m\n\n");
    }
    
    /* Phase 1: Per-flow analysis */
    if (dpi_engine->flow_count <= 10000) {
        printf("[Rule Engine] Performing detailed analysis on %u flows...\n", dpi_engine->flow_count);
        for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
            const flow_stats_t *flow = &dpi_engine->flows[i];
            
            ip_statistics_t *src_stats = get_or_create_ip_stats(engine, flow->src_ip);
            if (src_stats) {
                if (src_stats->first_seen.tv_sec == 0) {
                    src_stats->first_seen = flow->first_seen;
                }
                src_stats->last_seen = flow->last_seen;
                
                if (flow->protocol == 6) {
                    src_stats->total_syn_packets += flow->syn_count;
                    src_stats->total_ack_packets += flow->ack_count;
                } else if (flow->protocol == 17) {
                    src_stats->total_udp_packets += (uint32_t)flow->total_packets;
                } else if (flow->protocol == 1) {
                    src_stats->total_icmp_packets += (uint32_t)flow->total_packets;
                }
                
                if (src_stats->unique_dst_port_count < 1024) {
                    int found = 0;
                    for (uint32_t j = 0; j < src_stats->unique_dst_port_count; j++) {
                        if (src_stats->unique_dst_ports[j] == flow->dst_port) {
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        src_stats->unique_dst_ports[src_stats->unique_dst_port_count++] = flow->dst_port;
                    }
                }
            }
            
            rule_engine_analyze_flow(engine, flow);
            
            if ((i + 1) % 500 == 0) {
                printf("[Rule Engine] Analyzed %u / %u flows (%.1f%% complete)...\n",
                       i + 1, dpi_engine->flow_count,
                       ((float)(i + 1) / dpi_engine->flow_count) * 100.0);
            }
        }
        
        check_and_block_flood_sources(engine);
    } else {
        printf("[Rule Engine] Sampling analysis (too many flows for full scan)...\n");
        uint32_t sample_interval = dpi_engine->flow_count / 1000;
        for (uint32_t i = 0; i < dpi_engine->flow_count; i += sample_interval) {
            rule_engine_analyze_flow(engine, &dpi_engine->flows[i]);
        }
    }
    
    /* Phase 2: Aggregate analysis */
    printf("\n[Rule Engine] Running aggregate attack detection across all flows...\n");
    detect_aggregate_syn_flood(engine, dpi_engine);
    
    /* Phase 3: Aggregate volumetric flood detection for distributed attacks */
    {
        /* Group by (dst_ip, protocol, dst_port) for floods */
        typedef struct { uint32_t dst_ip; uint64_t total_pkts; uint64_t total_bytes;
            uint32_t flow_count; uint8_t protocol; uint16_t dst_port; uint16_t common_src_port; } agg_t;
        agg_t agg[5000];
        uint32_t agg_count = 0;
        
        /* Group by (src_ip→dst_ip) for scan detection */
        typedef struct { uint32_t src_ip; uint32_t dst_ip; uint32_t flow_count;
            uint16_t ports[512]; uint32_t port_count; uint8_t protocol;
            uint32_t syn_count; uint32_t fin_count; uint32_t ack_count; uint32_t rst_count;
            uint32_t psh_count; uint32_t urg_count; /* for Xmas scan distinction */
            uint32_t has_flags_zero; } scan_agg_t;
        scan_agg_t scans[1000];
        uint32_t scan_count = 0;
        
        for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
            const flow_stats_t *fl = &dpi_engine->flows[i];
            
            /* Flood aggregation — protocol-aware grouping key:
             *   TCP:  group by (dst_ip, proto, dst_port) — keeps HTTP:80 separate from SYN:1883
             *   UDP:  group by (dst_ip, proto, amp_src_port) — keeps DNS:53 separate from NTP:123
             *   ICMP: group by (dst_ip, proto) */
            uint16_t fl_amp_src = (fl->protocol == IPPROTO_UDP &&
                (fl->src_port == 53 || fl->src_port == 123 || fl->src_port == 19))
                ? fl->src_port : 0;
            int found = -1;
            for (uint32_t j = 0; j < agg_count; j++) {
                if (agg[j].dst_ip != fl->dst_ip || agg[j].protocol != fl->protocol) continue;
                if (fl->protocol == IPPROTO_TCP && agg[j].dst_port != fl->dst_port) continue;
                if (fl->protocol == IPPROTO_UDP && agg[j].common_src_port != fl_amp_src) continue;
                found = j; break;
            }
            if (found >= 0) {
                agg[found].total_pkts += fl->total_packets;
                agg[found].total_bytes += fl->total_bytes;
                agg[found].flow_count++;
            } else if (agg_count < 5000) {
                memset(&agg[agg_count], 0, sizeof(agg_t));
                agg[agg_count].dst_ip = fl->dst_ip; agg[agg_count].total_pkts = fl->total_packets;
                agg[agg_count].total_bytes = fl->total_bytes; agg[agg_count].flow_count = 1;
                agg[agg_count].protocol = fl->protocol; agg[agg_count].dst_port = fl->dst_port;
                agg[agg_count].common_src_port = fl_amp_src;
                agg_count++;
            }
            
            /* Scan aggregation — group by (src→dst) to count unique ports */
            found = -1;
            for (uint32_t j = 0; j < scan_count; j++) {
                if (scans[j].src_ip == fl->src_ip && scans[j].dst_ip == fl->dst_ip && scans[j].protocol == fl->protocol) {
                    found = j; break;
                }
            }
            if (found >= 0) {
                scans[found].flow_count++;
                scans[found].syn_count += fl->syn_count;
                scans[found].fin_count += fl->fin_count;
                scans[found].ack_count += fl->ack_count;
                scans[found].rst_count += fl->rst_count;
                scans[found].psh_count += fl->psh_count;
                scans[found].urg_count += fl->urg_count;
                if (fl->syn_count == 0 && fl->ack_count == 0 && fl->fin_count == 0 && fl->rst_count == 0
                    && fl->psh_count == 0 && fl->urg_count == 0)
                    scans[found].has_flags_zero++;
                /* Track unique dst ports */
                int pf = 0;
                for (uint32_t k = 0; k < scans[found].port_count; k++)
                    if (scans[found].ports[k] == fl->dst_port) { pf = 1; break; }
                if (!pf && scans[found].port_count < 512)
                    scans[found].ports[scans[found].port_count++] = fl->dst_port;
            } else if (scan_count < 1000) {
                memset(&scans[scan_count], 0, sizeof(scan_agg_t));
                scans[scan_count].src_ip = fl->src_ip; scans[scan_count].dst_ip = fl->dst_ip;
                scans[scan_count].protocol = fl->protocol; scans[scan_count].flow_count = 1;
                scans[scan_count].syn_count = fl->syn_count; scans[scan_count].fin_count = fl->fin_count;
                scans[scan_count].ack_count = fl->ack_count; scans[scan_count].rst_count = fl->rst_count;
                scans[scan_count].psh_count = fl->psh_count; scans[scan_count].urg_count = fl->urg_count;
                scans[scan_count].ports[0] = fl->dst_port; scans[scan_count].port_count = 1;
                if (fl->syn_count == 0 && fl->ack_count == 0 && fl->fin_count == 0 && fl->rst_count == 0
                    && fl->psh_count == 0 && fl->urg_count == 0)
                    scans[scan_count].has_flags_zero = 1;
                scan_count++;
            }
        }
        
        /* Process flood aggregates */
        for (uint32_t i = 0; i < agg_count; i++) {
            if (agg[i].flow_count < 50) continue;
            attack_detection_t det; memset(&det, 0, sizeof(det));
            det.target_ip = agg[i].dst_ip; det.dst_port = agg[i].dst_port; det.protocol = agg[i].protocol;
            det.packet_count = agg[i].total_pkts; det.byte_count = agg[i].total_bytes;
            det.confidence_score = fmin(1.0, (double)agg[i].flow_count / 500.0);
            det.detection_time = dpi_engine->flows[0].last_seen;
            uint64_t avg_sz = agg[i].total_pkts > 0 ? agg[i].total_bytes / agg[i].total_pkts : 0;
            
            if (agg[i].protocol == IPPROTO_UDP) {
                if (agg[i].common_src_port == 53 && avg_sz > 200 && agg[i].flow_count > 50) {
                    det.attack_type = ATTACK_DNS_AMPLIFICATION; det.severity = SEVERITY_HIGH;
                    strcpy(det.attack_name, "DNS Amplification Attack");
                    strncpy(det.rfc_reference, "RFC 5358", sizeof(det.rfc_reference)-1);
                    snprintf(det.description, sizeof(det.description), "Aggregate DNS amp: %u flows, %lu pkts, avg %lu B", agg[i].flow_count, agg[i].total_pkts, avg_sz);
                    add_detection(engine, &det);
                } else if (agg[i].common_src_port == 123 && avg_sz > 200 && agg[i].flow_count > 50) {
                    det.attack_type = ATTACK_NTP_AMPLIFICATION; det.severity = SEVERITY_HIGH;
                    strcpy(det.attack_name, "NTP Amplification Attack");
                    strncpy(det.rfc_reference, "RFC 5905, CVE-2013-5211", sizeof(det.rfc_reference)-1);
                    snprintf(det.description, sizeof(det.description), "Aggregate NTP amp: %u flows, %lu pkts, avg %lu B", agg[i].flow_count, agg[i].total_pkts, avg_sz);
                    add_detection(engine, &det);
                } else if (agg[i].flow_count > 100) {
                    det.attack_type = ATTACK_UDP_FLOOD; det.severity = SEVERITY_HIGH;
                    strcpy(det.attack_name, "UDP Flood Attack");
                    strncpy(det.rfc_reference, "RFC 768, RFC 4732", sizeof(det.rfc_reference)-1);
                    snprintf(det.description, sizeof(det.description), "Aggregate UDP flood: %u sources, %lu pkts", agg[i].flow_count, agg[i].total_pkts);
                    add_detection(engine, &det);
                }
            } else if (agg[i].protocol == IPPROTO_ICMP && agg[i].flow_count > 100) {
                det.attack_type = ATTACK_ICMP_FLOOD; det.severity = SEVERITY_HIGH;
                strcpy(det.attack_name, "ICMP Flood Attack");
                strncpy(det.rfc_reference, "RFC 792, RFC 4732", sizeof(det.rfc_reference)-1);
                snprintf(det.description, sizeof(det.description), "Aggregate ICMP flood: %u sources, %lu pkts", agg[i].flow_count, agg[i].total_pkts);
                add_detection(engine, &det);
            } else if (agg[i].protocol == IPPROTO_TCP && agg[i].flow_count > 100) {
                if (agg[i].dst_port == 80 || agg[i].dst_port == 8080) {
                    det.attack_type = ATTACK_HTTP_FLOOD; det.severity = SEVERITY_HIGH;
                    strcpy(det.attack_name, "HTTP Flood Attack");
                    strncpy(det.rfc_reference, "RFC 9110, RFC 4732", sizeof(det.rfc_reference)-1);
                    snprintf(det.description, sizeof(det.description), "Aggregate HTTP flood: %u sources, %lu pkts", agg[i].flow_count, agg[i].total_pkts);
                    add_detection(engine, &det);
                }
            }
        }
        
        /* Process scan aggregates (1 source → many unique ports) */
        for (uint32_t i = 0; i < scan_count; i++) {
            /* Threshold: min unique ports to classify as scan (configured, default 5) */
            if (scans[i].port_count < engine->thresholds.port_scan_unique_ports) continue;
            
            attack_detection_t det; memset(&det, 0, sizeof(det));
            det.attacker_ip = scans[i].src_ip; det.target_ip = scans[i].dst_ip;
            det.protocol = scans[i].protocol; det.packet_count = scans[i].flow_count;
            det.detection_time = dpi_engine->flows[0].last_seen;
            det.confidence_score = fmin(1.0, (double)scans[i].port_count / 50.0);
            
            if (scans[i].protocol == IPPROTO_TCP) {
                if (scans[i].fin_count > 0 && scans[i].syn_count == 0 && scans[i].ack_count == 0) {
                    /* Xmas scan (FIN+PSH+URG) or FIN-only scan — distinguished by PSH/URG */
                    int is_xmas = (scans[i].psh_count > 0 || scans[i].urg_count > 0);
                    det.attack_type = is_xmas ? ATTACK_XMAS_SCAN : ATTACK_FIN_SCAN;
                    det.severity = SEVERITY_HIGH;
                    strcpy(det.attack_name, is_xmas ? "Xmas Tree Scan" : "FIN Scan");
                    strncpy(det.rfc_reference, "RFC 793 S3.9", sizeof(det.rfc_reference)-1);
                    snprintf(det.description, sizeof(det.description),
                        "Aggregate %s: %u unique ports (FIN:%u PSH:%u URG:%u)",
                        is_xmas ? "Xmas scan" : "FIN scan",
                        scans[i].port_count, scans[i].fin_count, scans[i].psh_count, scans[i].urg_count);
                    add_detection(engine, &det);
                } else if (scans[i].has_flags_zero > scans[i].flow_count / 2) {
                    det.attack_type = ATTACK_NULL_SCAN; det.severity = SEVERITY_HIGH;
                    strcpy(det.attack_name, "NULL Scan"); strncpy(det.rfc_reference, "RFC 793 S3.9", sizeof(det.rfc_reference)-1);
                    snprintf(det.description, sizeof(det.description), "Aggregate NULL scan: %u unique ports, %u zero-flag pkts", scans[i].port_count, scans[i].has_flags_zero);
                    add_detection(engine, &det);
                } else if (scans[i].syn_count > 0 && scans[i].ack_count > scans[i].syn_count / 2) {
                    det.attack_type = ATTACK_TCP_CONNECT_SCAN; det.severity = SEVERITY_MEDIUM;
                    strcpy(det.attack_name, "TCP Connect Scan"); strncpy(det.rfc_reference, "RFC 793", sizeof(det.rfc_reference)-1);
                    snprintf(det.description, sizeof(det.description), "Aggregate connect scan: %u ports, SYN:%u ACK:%u", scans[i].port_count, scans[i].syn_count, scans[i].ack_count);
                    add_detection(engine, &det);
                } else if (scans[i].syn_count > 0) {
                    det.attack_type = ATTACK_TCP_SYN_SCAN; det.severity = SEVERITY_MEDIUM;
                    strcpy(det.attack_name, "TCP SYN Scan"); strncpy(det.rfc_reference, "RFC 793 S3.9", sizeof(det.rfc_reference)-1);
                    snprintf(det.description, sizeof(det.description), "Aggregate SYN scan: %u unique ports", scans[i].port_count);
                    add_detection(engine, &det);
                }
            } else if (scans[i].protocol == IPPROTO_UDP) {
                det.attack_type = ATTACK_UDP_SCAN; det.severity = SEVERITY_MEDIUM;
                strcpy(det.attack_name, "UDP Scan"); strncpy(det.rfc_reference, "RFC 768", sizeof(det.rfc_reference)-1);
                snprintf(det.description, sizeof(det.description), "Aggregate UDP scan: %u unique ports", scans[i].port_count);
                add_detection(engine, &det);
            }
        }

        /* Phase 3 — ARP Spoofing: detect IPs with multiple MAC addresses in ip_stats
         * (populated by rule_engine_process_arp_pcap() pre-pass in batch mode,
         *  or by update_ip_statistics() per-packet in live-capture mode) */
        for (uint32_t i = 0; i < engine->ip_stats_count; i++) {
            ip_statistics_t *ips = &engine->ip_stats[i];
            if (ips->mac_address_count >= engine->thresholds.arp_spoofing_mac_changes) {
                attack_detection_t det; memset(&det, 0, sizeof(det));
                det.attack_type = ATTACK_ARP_SPOOFING; det.severity = SEVERITY_CRITICAL;
                strcpy(det.attack_name, "ARP Spoofing");
                strncpy(det.rfc_reference, "RFC 826, RFC 5227", sizeof(det.rfc_reference)-1);
                det.attacker_ip = ips->ip_address;
                det.packet_count = ips->mac_address_count;
                det.confidence_score = fmin(1.0, (double)ips->mac_address_count / 10.0);
                if (dpi_engine->flow_count > 0)
                    det.detection_time = dpi_engine->flows[0].last_seen;
                snprintf(det.description, sizeof(det.description),
                    "ARP Spoofing per RFC 826/5227: IP %s claims %u different MACs (threshold: %u)",
                    inet_ntoa((struct in_addr){.s_addr = htonl(ips->ip_address)}),
                    ips->mac_address_count, engine->thresholds.arp_spoofing_mac_changes);
                snprintf(det.details, sizeof(det.details),
                    "IP:%s MACcount:%u (Multiple MACs = cache poisoning / spoofed gratuitous ARP)",
                    inet_ntoa((struct in_addr){.s_addr = htonl(ips->ip_address)}),
                    ips->mac_address_count);
                add_detection(engine, &det);
            }
        }
    }
    
    printf("[Rule Engine] Analysis complete. Total attacks detected: %lu\n",
           engine->total_attacks_detected);
}

void rule_engine_analyze_flow(rule_engine_t *engine, const flow_stats_t *flow) {
    attack_detection_t detection;
    int attack_found = 0;
    
    /* === Volumetric / Flooding Attacks === */
    if (detect_syn_flood(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_udp_flood(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_icmp_flood(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_http_flood(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_dns_amplification(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_ntp_amplification(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_smurf_attack(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_fraggle_attack(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    
    /* === Protocol Exploitation === */
    if (detect_ping_of_death(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_land_attack(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_teardrop_attack(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_ip_spoofing(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    
    /* === Reconnaissance / Scanning === */
    if (detect_tcp_syn_scan(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_tcp_connect_scan(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_udp_scan(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_xmas_scan(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_null_scan(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_fin_scan(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    
    /* === Application-Layer === */
    if (detect_rudy_attack(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    if (detect_slowloris(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    
    /* === Layer 2 === */
    if (detect_arp_spoofing(engine, flow, &detection)) {
        add_detection(engine, &detection); attack_found = 1;
    }
    
    if (attack_found) {
        printf("\n┌────────────────────────────────────────────────────────────────┐\n");
        printf("│    ⚠️  ATTACK DETECTED IN FLOW                                     │\n");
        printf("└────────────────────────────────────────────────────────────────┘\n");
        printf("  Source:      %s:%u\n",
               inet_ntoa((struct in_addr){.s_addr = htonl(flow->src_ip)}),
               flow->src_port);
        printf("  Destination: %s:%u\n",
               inet_ntoa((struct in_addr){.s_addr = htonl(flow->dst_ip)}),
               flow->dst_port);
        printf("  Protocol:    %s\n", flow->protocol_name);
        printf("  Packets:     %lu (SYN:%u ACK:%u FIN:%u RST:%u)\n",
               flow->total_packets, flow->syn_count, flow->ack_count,
               flow->fin_count, flow->rst_count);
        printf("  Bytes:       %lu\n", flow->total_bytes);
        printf("  Duration:    %.3fs\n",
               (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
               (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0);
        printf("────────────────────────────────────────────────────────────────\n\n");
    }
}

/* ========== ARP Batch Processing (for PCAP mode ARP Spoofing detection) ========== */
/*
 * Performs a second pass over the PCAP file looking only for ARP packets.
 * Extracts sender-MAC → sender-IP mappings and populates ip_stats[].mac_addresses
 * so that detect_arp_spoofing() can find multiple MACs claiming the same IP.
 *
 * ARP frame layout (after Ethernet header, ethertype 0x0806):
 *   [0-1] HW type (2B)  [2-3] Proto type (2B)  [4] HW size  [5] Proto size  [6-7] Opcode
 *   [8-13]  Sender MAC (6B)   [14-17] Sender IP (4B)
 *   [18-23] Target MAC (6B)   [24-27] Target IP (4B)
 */
void rule_engine_process_arp_pcap(rule_engine_t *engine, const char *pcap_file) {
    if (!engine || !pcap_file) return;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) return;

    int datalink = pcap_datalink(handle);
    if (datalink != DLT_EN10MB) { pcap_close(handle); return; }

    const uint8_t *packet;
    struct pcap_pkthdr *header;
    uint32_t arp_entries = 0;

    while (pcap_next_ex(handle, &header, &packet) > 0) {
        if (header->caplen < 42) continue;  /* Ethernet(14) + ARP(28) minimum */

        uint16_t ethertype = (packet[12] << 8) | packet[13];
        if (ethertype != 0x0806) continue;  /* Not ARP */

        const uint8_t *arp = packet + 14;
        uint16_t hw_type    = (arp[0] << 8) | arp[1];
        uint16_t proto_type = (arp[2] << 8) | arp[3];
        if (hw_type != 1 || proto_type != 0x0800) continue; /* Ethernet/IPv4 ARP only */

        const uint8_t *sender_mac = arp + 8;
        uint32_t sender_ip_net;
        memcpy(&sender_ip_net, arp + 14, 4);
        uint32_t sender_ip = ntohl(sender_ip_net);

        ip_statistics_t *stats = get_or_create_ip_stats(engine, sender_ip);
        if (!stats) continue;

        int already_known = 0;
        for (uint32_t i = 0; i < stats->mac_address_count; i++) {
            if (memcmp(stats->mac_addresses[i], sender_mac, 6) == 0) {
                already_known = 1; break;
            }
        }
        if (!already_known && stats->mac_address_count < 10) {
            memcpy(stats->mac_addresses[stats->mac_address_count++], sender_mac, 6);
            arp_entries++;
        }
    }

    pcap_close(handle);
    if (arp_entries > 0)
        printf("[Rule Engine] ARP pre-scan: %u unique sender-MAC/IP mappings indexed\n", arp_entries);
}
