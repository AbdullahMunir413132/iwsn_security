/*
 * Rule Engine - Attack Detection Implementations (Part 1: Existing + New Volumetric)
 * RFC-Compliant detection algorithms for each attack type
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include "rule_engine.h"

/* ========== SYN Flood Detection (RFC 4987, RFC 793) ========== */
int detect_syn_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                     attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_TCP) return 0;
    
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) +
                     (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
    if (duration < 0.1) duration = 0.1;
    
    double syn_rate = (double)flow->syn_count / duration;
    double syn_ack_ratio = 0.0;
    if (flow->ack_count > 0) {
        syn_ack_ratio = (double)flow->syn_count / (double)flow->ack_count;
    } else if (flow->syn_count > 0) {
        syn_ack_ratio = 999.0;
    }
    
    if (syn_rate > engine->thresholds.syn_flood_threshold &&
        syn_ack_ratio > engine->thresholds.syn_flood_ratio) {
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_SYN_FLOOD;
        detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "SYN Flood Attack");
        strncpy(detection->rfc_reference, "RFC 4987, RFC 793", sizeof(detection->rfc_reference)-1);
        
        snprintf(detection->description, sizeof(detection->description),
                "SYN flood per RFC 4987: %.2f SYN/sec, SYN:ACK ratio %.2f:1 (threshold: %u/s, ratio %.1f)",
                syn_rate, syn_ack_ratio, engine->thresholds.syn_flood_threshold, engine->thresholds.syn_flood_ratio);
        
        detection->attacker_ip = flow->src_ip;  detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port;    detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol;
        detection->packet_count = flow->syn_count; detection->byte_count = flow->total_bytes;
        detection->packets_per_second = syn_rate;  detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0, 
            (syn_rate / (engine->thresholds.syn_flood_threshold * 2.0)) * 
            (syn_ack_ratio / (engine->thresholds.syn_flood_ratio * 2.0)));
        
        snprintf(detection->details, sizeof(detection->details),
                "SYN:%u ACK:%u Attempts:%u Duration:%.2fs", flow->syn_count, flow->ack_count, flow->connection_attempts, duration);
        return 1;
    }
    return 0;
}

/* ========== Aggregate SYN Flood Detection ========== */
void detect_aggregate_syn_flood(rule_engine_t *engine, const dpi_engine_t *dpi_engine) {
    typedef struct { uint32_t dst_ip; uint32_t total_syn_count; uint32_t flow_count;
        uint32_t syn_only_flows; uint64_t total_bytes; double first_seen; double last_seen;
        uint32_t attacker_ips[100]; uint32_t attacker_count; } target_syn_stats_t;
    
    target_syn_stats_t targets[10000];
    uint32_t target_count = 0;
    
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        const flow_stats_t *flow = &dpi_engine->flows[i];
        if (flow->protocol != IPPROTO_TCP || flow->syn_count == 0) continue;
        
        int found = -1;
        for (uint32_t j = 0; j < target_count; j++) {
            if (targets[j].dst_ip == flow->dst_ip) { found = j; break; }
        }
        if (found < 0) {
            if (target_count >= 10000) continue;
            found = target_count++;
            memset(&targets[found], 0, sizeof(target_syn_stats_t));
            targets[found].dst_ip = flow->dst_ip;
            targets[found].first_seen = flow->first_seen.tv_sec + flow->first_seen.tv_usec / 1000000.0;
            targets[found].last_seen = flow->last_seen.tv_sec + flow->last_seen.tv_usec / 1000000.0;
        }
        targets[found].total_syn_count += flow->syn_count;
        targets[found].flow_count++;
        targets[found].total_bytes += flow->total_bytes;
        
        if (targets[found].attacker_count < 100) {
            int already = 0;
            for (uint32_t k = 0; k < targets[found].attacker_count; k++)
                if (targets[found].attacker_ips[k] == flow->src_ip) { already = 1; break; }
            if (!already) targets[found].attacker_ips[targets[found].attacker_count++] = flow->src_ip;
        }
        double fl = flow->first_seen.tv_sec + flow->first_seen.tv_usec/1e6;
        double ll = flow->last_seen.tv_sec + flow->last_seen.tv_usec/1e6;
        if (fl < targets[found].first_seen) targets[found].first_seen = fl;
        if (ll > targets[found].last_seen) targets[found].last_seen = ll;
        if (flow->ack_count == 0 && flow->syn_count > 0) targets[found].syn_only_flows++;
    }
    
    /* Network scan detection */
    if (target_count > 100) {
        uint32_t common_attackers[10]; uint32_t cac = 0;
        for (uint32_t i = 0; i < target_count && i < 100; i++)
            for (uint32_t j = 0; j < targets[i].attacker_count && j < 5; j++) {
                uint32_t aip = targets[i].attacker_ips[j]; int ac = 0;
                for (uint32_t k = 0; k < cac; k++) if (common_attackers[k] == aip) { ac = 1; break; }
                if (!ac && cac < 10) common_attackers[cac++] = aip;
            }
        if (cac <= 10 && cac > 0) {
            attack_detection_t det; memset(&det, 0, sizeof(det));
            det.attack_type = ATTACK_TCP_CONNECT_SCAN; det.severity = SEVERITY_HIGH;
            strcpy(det.attack_name, "TCP Network Scan");
            strncpy(det.rfc_reference, "RFC 793 S3.9", sizeof(det.rfc_reference)-1);
            uint32_t ts=0,tf=0,tso=0; uint64_t tb=0;
            for (uint32_t i=0;i<target_count;i++){ts+=targets[i].total_syn_count;tf+=targets[i].flow_count;tso+=targets[i].syn_only_flows;tb+=targets[i].total_bytes;}
            snprintf(det.description, sizeof(det.description), "Network scan: %u targets from %u sources, %u SYN packets", target_count, cac, ts);
            det.attacker_ip = common_attackers[0]; det.protocol = IPPROTO_TCP;
            det.packet_count = ts; det.byte_count = tb;
            det.confidence_score = fmin(1.0, (double)target_count / 1000.0);
            add_detection(engine, &det);
            for (uint32_t j = 0; j < cac; j++) block_ip(engine, common_attackers[j]);
            return;
        }
    }
    
    /* Per-target distributed flood check */
    for (uint32_t i = 0; i < target_count; i++) {
        double dur = targets[i].last_seen - targets[i].first_seen;
        if (dur < 0.1) dur = 0.1;
        double sr = (double)targets[i].total_syn_count / dur;
        double sor = (double)targets[i].syn_only_flows / (double)targets[i].flow_count;
        if ((sr > 20.0 && targets[i].flow_count > 10) || (targets[i].syn_only_flows > 15 && sor > 0.7)) {
            attack_detection_t det; memset(&det, 0, sizeof(det));
            det.attack_type = ATTACK_SYN_FLOOD; det.severity = SEVERITY_HIGH;
            strcpy(det.attack_name, "Distributed SYN Flood");
            strncpy(det.rfc_reference, "RFC 4987, RFC 793", sizeof(det.rfc_reference)-1);
            snprintf(det.description, sizeof(det.description),
                "Distributed SYN flood: %u SYNs across %u flows from %u sources (%.2f SYN/s)",
                targets[i].total_syn_count, targets[i].flow_count, targets[i].attacker_count, sr);
            det.target_ip = targets[i].dst_ip;
            det.attacker_ip = targets[i].attacker_count > 0 ? targets[i].attacker_ips[0] : 0;
            det.protocol = IPPROTO_TCP; det.packet_count = targets[i].total_syn_count;
            det.byte_count = targets[i].total_bytes; det.packets_per_second = sr;
            det.duration_seconds = dur;
            det.confidence_score = fmax(fmin(1.0, sr/100.0), fmin(1.0, sor/10.0)*0.8);
            add_detection(engine, &det);
            for (uint32_t j = 0; j < targets[i].attacker_count; j++) block_ip(engine, targets[i].attacker_ips[j]);
        }
    }
}

/* ========== UDP Flood Detection (RFC 768, RFC 4732) ========== */
int detect_udp_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_UDP) return 0;
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < 0.1) duration = 0.1;
    double rate = (double)flow->total_packets / duration;
    if (rate > engine->thresholds.udp_flood_threshold && flow->total_packets > engine->thresholds.udp_flood_packet_count) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_UDP_FLOOD; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "UDP Flood Attack");
        strncpy(detection->rfc_reference, "RFC 768, RFC 4732", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description), "UDP flood per RFC 4732: %.2f pkt/s (threshold: %u)", rate, engine->thresholds.udp_flood_threshold);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port; detection->dst_port = flow->dst_port; detection->protocol = flow->protocol;
        detection->packet_count = flow->total_packets; detection->byte_count = flow->total_bytes;
        detection->packets_per_second = rate; detection->duration_seconds = duration; detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0, rate / (engine->thresholds.udp_flood_threshold * 2.0));
        snprintf(detection->details, sizeof(detection->details), "Packets:%lu Bytes:%lu Rate:%.2f Duration:%.2fs", flow->total_packets, flow->total_bytes, rate, duration);
        return 1;
    }
    return 0;
}

/* ========== HTTP Flood Detection (RFC 9110) ========== */
int detect_http_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    int is_http = (flow->dst_port == 80 || flow->dst_port == 8080 || strstr(flow->protocol_name, "HTTP") != NULL);
    if (!is_http || flow->protocol != IPPROTO_TCP) return 0;
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < 0.1) duration = 0.1;
    double rate = (double)flow->total_packets / duration;
    if (rate > engine->thresholds.http_flood_threshold) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_HTTP_FLOOD; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "HTTP Flood Attack");
        strncpy(detection->rfc_reference, "RFC 9110, RFC 4732", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description), "HTTP flood per RFC 9110: %.2f req/s (threshold: %u)", rate, engine->thresholds.http_flood_threshold);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port; detection->dst_port = flow->dst_port; detection->protocol = flow->protocol;
        detection->packet_count = flow->total_packets; detection->byte_count = flow->total_bytes;
        detection->packets_per_second = rate; detection->duration_seconds = duration; detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0, rate / (engine->thresholds.http_flood_threshold * 2.0));
        snprintf(detection->details, sizeof(detection->details), "HTTP Pkts:%lu Port:%u Rate:%.2f Duration:%.2fs", flow->total_packets, flow->dst_port, rate, duration);
        return 1;
    }
    return 0;
}

/* ========== ICMP Flood Detection (RFC 792) ========== */
int detect_icmp_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_ICMP) return 0;
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < 0.1) duration = 0.1;
    double rate = (double)flow->total_packets / duration;
    if (rate > engine->thresholds.icmp_flood_threshold) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_ICMP_FLOOD; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "ICMP Flood Attack");
        strncpy(detection->rfc_reference, "RFC 792, RFC 4732", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description), "ICMP flood per RFC 792: %.2f pkt/s (threshold: %u)", rate, engine->thresholds.icmp_flood_threshold);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip; detection->protocol = flow->protocol;
        detection->packet_count = flow->total_packets; detection->byte_count = flow->total_bytes;
        detection->packets_per_second = rate; detection->duration_seconds = duration; detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0, rate / (engine->thresholds.icmp_flood_threshold * 2.0));
        snprintf(detection->details, sizeof(detection->details), "ICMP Pkts:%lu Bytes:%lu Rate:%.2f Duration:%.2fs", flow->total_packets, flow->total_bytes, rate, duration);
        return 1;
    }
    return 0;
}

/* ========== Ping of Death Detection (RFC 791 §3.2) ========== */
int detect_ping_of_death(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_ICMP) return 0;
    if (flow->max_packet_size > engine->thresholds.pod_packet_size) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_PING_OF_DEATH; detection->severity = SEVERITY_CRITICAL;
        strcpy(detection->attack_name, "Ping of Death");
        strncpy(detection->rfc_reference, "RFC 791 S3.2, RFC 6274", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "Ping of Death per RFC 791 S3.2: %u bytes exceeds max IP datagram (65535)", flow->max_packet_size);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip; detection->protocol = flow->protocol;
        detection->packet_count = flow->total_packets; detection->byte_count = flow->total_bytes;
        detection->detection_time = flow->last_seen; detection->confidence_score = 1.0;
        snprintf(detection->details, sizeof(detection->details), "Max ICMP:%u bytes (RFC 791 limit: 65535)", flow->max_packet_size);
        return 1;
    }
    return 0;
}

/* ========== ARP Spoofing Detection (RFC 826, RFC 5227) ========== */
int detect_arp_spoofing(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    ip_statistics_t *ip_stats = NULL;
    for (uint32_t i = 0; i < engine->ip_stats_count; i++) {
        if (engine->ip_stats[i].ip_address == flow->src_ip) { ip_stats = &engine->ip_stats[i]; break; }
    }
    if (!ip_stats) return 0;
    if (ip_stats->mac_address_count >= engine->thresholds.arp_spoofing_mac_changes) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_ARP_SPOOFING; detection->severity = SEVERITY_CRITICAL;
        strcpy(detection->attack_name, "ARP Spoofing");
        strncpy(detection->rfc_reference, "RFC 826, RFC 5227", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "ARP spoofing per RFC 5227: %u MACs for single IP (threshold: %u)", ip_stats->mac_address_count, engine->thresholds.arp_spoofing_mac_changes);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->detection_time = flow->last_seen; detection->confidence_score = 0.9;
        char ml[256] = "";
        for (uint32_t i = 0; i < ip_stats->mac_address_count && i < 5; i++) {
            char ms[32]; snprintf(ms, sizeof(ms), "%02x:%02x:%02x:%02x:%02x:%02x ",
                ip_stats->mac_addresses[i][0], ip_stats->mac_addresses[i][1], ip_stats->mac_addresses[i][2],
                ip_stats->mac_addresses[i][3], ip_stats->mac_addresses[i][4], ip_stats->mac_addresses[i][5]);
            strcat(ml, ms);
        }
        snprintf(detection->details, sizeof(detection->details), "IP has %u MACs: %s", ip_stats->mac_address_count, ml);
        return 1;
    }
    return 0;
}

/* ========== RUDY Slow POST (RFC 9110) ========== */
int detect_rudy_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    int is_http = (flow->dst_port == 80 || flow->dst_port == 8080 || strstr(flow->protocol_name, "HTTP") != NULL);
    if (!is_http || flow->protocol != IPPROTO_TCP || flow->total_packets < engine->thresholds.rudy_min_packets) return 0;
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < 1.0) return 0;
    double avg_rate = (double)flow->total_bytes / duration;
    if (avg_rate < engine->thresholds.rudy_avg_body_rate && duration > engine->thresholds.rudy_time_window) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_RUDY; detection->severity = SEVERITY_MEDIUM;
        strcpy(detection->attack_name, "RUDY (Slow POST) Attack");
        strncpy(detection->rfc_reference, "RFC 9110, OWASP", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description), "RUDY per RFC 9110: %.2f bytes/s over %.2fs", avg_rate, duration);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port; detection->dst_port = flow->dst_port; detection->protocol = flow->protocol;
        detection->packet_count = flow->total_packets; detection->byte_count = flow->total_bytes;
        detection->duration_seconds = duration; detection->detection_time = flow->last_seen; detection->confidence_score = 0.7;
        snprintf(detection->details, sizeof(detection->details), "Pkts:%lu Rate:%.2f B/s Duration:%.2fs", flow->total_packets, avg_rate, duration);
        return 1;
    }
    return 0;
}

/* ========== TCP SYN Scan (RFC 793) ========== */
int detect_tcp_syn_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_TCP) return 0;
    if (flow->syn_count > 5 && flow->rst_count > 0 && flow->ack_count < (flow->syn_count * 0.3)) {
        if (flow->unique_dst_port_count >= engine->thresholds.tcp_connect_scan_ports) {
            memset(detection, 0, sizeof(attack_detection_t));
            detection->attack_type = ATTACK_TCP_SYN_SCAN; detection->severity = SEVERITY_MEDIUM;
            strcpy(detection->attack_name, "TCP SYN Scan");
            strncpy(detection->rfc_reference, "RFC 793 S3.9", sizeof(detection->rfc_reference)-1);
            snprintf(detection->description, sizeof(detection->description), "SYN scan per RFC 793: %u ports scanned", flow->unique_dst_port_count);
            detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip; detection->protocol = flow->protocol;
            detection->packet_count = flow->total_packets; detection->detection_time = flow->last_seen;
            detection->duration_seconds = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
            detection->confidence_score = fmin(1.0, (double)flow->unique_dst_port_count / 50.0);
            snprintf(detection->details, sizeof(detection->details), "SYN:%u RST:%u ACK:%u Ports:%u", flow->syn_count, flow->rst_count, flow->ack_count, flow->unique_dst_port_count);
            return 1;
        }
    }
    return 0;
}

/* ========== TCP Connect Scan (RFC 793) ========== */
int detect_tcp_connect_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_TCP) return 0;
    if (flow->unique_dst_port_count >= engine->thresholds.tcp_connect_scan_ports) {
        double cr = flow->syn_count > 0 ? (double)flow->ack_count / (double)flow->syn_count : 0;
        if (cr > engine->thresholds.tcp_connect_scan_completion) {
            memset(detection, 0, sizeof(attack_detection_t));
            detection->attack_type = ATTACK_TCP_CONNECT_SCAN; detection->severity = SEVERITY_MEDIUM;
            strcpy(detection->attack_name, "TCP Connect Scan");
            strncpy(detection->rfc_reference, "RFC 793", sizeof(detection->rfc_reference)-1);
            snprintf(detection->description, sizeof(detection->description), "Connect scan: %u ports, completion %.2f", flow->unique_dst_port_count, cr);
            detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip; detection->protocol = flow->protocol;
            detection->packet_count = flow->total_packets; detection->detection_time = flow->last_seen;
            detection->duration_seconds = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
            detection->confidence_score = fmin(1.0, (double)flow->unique_dst_port_count / 50.0);
            snprintf(detection->details, sizeof(detection->details), "SYN:%u ACK:%u FIN:%u Ports:%u Completion:%.2f", flow->syn_count, flow->ack_count, flow->fin_count, flow->unique_dst_port_count, cr);
            return 1;
        }
    }
    return 0;
}

/* ========== UDP Scan (RFC 768) ========== */
int detect_udp_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_UDP) return 0;
    if (flow->unique_dst_port_count >= engine->thresholds.port_scan_unique_ports) {
        uint64_t avg_sz = flow->total_packets > 0 ? flow->total_packet_size / flow->total_packets : 0;
        if (avg_sz < 100) {
            memset(detection, 0, sizeof(attack_detection_t));
            detection->attack_type = ATTACK_UDP_SCAN; detection->severity = SEVERITY_MEDIUM;
            strcpy(detection->attack_name, "UDP Scan");
            strncpy(detection->rfc_reference, "RFC 768", sizeof(detection->rfc_reference)-1);
            snprintf(detection->description, sizeof(detection->description), "UDP scan: %u ports, avg %lu bytes", flow->unique_dst_port_count, avg_sz);
            detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip; detection->protocol = flow->protocol;
            detection->packet_count = flow->total_packets; detection->detection_time = flow->last_seen;
            detection->duration_seconds = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
            detection->confidence_score = fmin(1.0, (double)flow->unique_dst_port_count / 100.0);
            snprintf(detection->details, sizeof(detection->details), "Pkts:%lu Ports:%u AvgSize:%lu", flow->total_packets, flow->unique_dst_port_count, avg_sz);
            return 1;
        }
    }
    return 0;
}
