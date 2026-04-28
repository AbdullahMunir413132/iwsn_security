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

    /*
     * RFC 4987 §3 — Stateful half-open tracking
     *
     * A SYN flood fills the server's SYN backlog by sending SYN packets that
     * never complete the three-way handshake.  The canonical indicator is an
     * accumulation of *half-open* connections:
     *
     *   half_open = syn_count - syn_ack_count
     *
     * syn_ack_count counts the SYN+ACK replies seen in this flow
     * (tracked by update_flow_stats() in dpi_engine_flow.c).  When the ratio
     * of unanswered SYNs exceeds the threshold the backlog is under pressure.
     *
     * This is strictly more accurate than comparing SYN count to bare ACK
     * count, which over-fires on normal bidirectional TCP connections where
     * the ACK flag is present on every segment after the handshake.
     */
    uint32_t half_open = (flow->syn_count > flow->syn_ack_count)
                         ? (flow->syn_count - flow->syn_ack_count)
                         : 0;

    double syn_rate     = (double)flow->syn_count  / duration;

    /* Require BOTH: a high raw SYN rate AND a significant half-open ratio.
     * The half-open ratio guards against false-positives from normal
     * bi-directional traffic captured on the wire (where SYN-ACK replies
     * may belong to a different direction of the same flow). */
    double half_open_ratio = (flow->syn_count > 0)
                             ? (double)half_open / (double)flow->syn_count
                             : 0.0;

    if (syn_rate       > engine->thresholds.syn_flood_threshold &&
        half_open_ratio > (1.0 - 1.0 / engine->thresholds.syn_flood_ratio) &&
        half_open       >= 5) {   /* RFC 4987: require at least 5 absolute half-open
                                   * connections to suppress transient false positives
                                   * from short initial handshake delays */
        
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_SYN_FLOOD;
        detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "SYN Flood Attack");
        strncpy(detection->rfc_reference, "RFC 4987, RFC 793", sizeof(detection->rfc_reference)-1);
        
        snprintf(detection->description, sizeof(detection->description),
                "SYN flood per RFC 4987: %.1f SYN/s, %u half-open (%.0f%% incomplete) "
                "over %.2fs [threshold: %u/s]",
                syn_rate, half_open, half_open_ratio * 100.0, duration,
                engine->thresholds.syn_flood_threshold);
        
        detection->attacker_ip = flow->src_ip;  detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port;    detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol;
        detection->packet_count = flow->syn_count; detection->byte_count = flow->total_bytes;
        detection->packets_per_second = syn_rate;  detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0, half_open_ratio *
            (syn_rate / (engine->thresholds.syn_flood_threshold * 2.0)));
        
        snprintf(detection->details, sizeof(detection->details),
                "SYN:%u SYN-ACK:%u HalfOpen:%u ACK:%u Duration:%.2fs",
                flow->syn_count, flow->syn_ack_count, half_open,
                flow->ack_count, duration);
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
        /* Bug fix: was hardcoded 20.0 and 15 — now driven by engine thresholds.
         * Aggregate threshold = 40 % of the per-flow threshold because a
         * distributed flood spreads SYNs across multiple source IPs (each
         * contributing fewer packets per flow), so the per-target aggregate
         * rate is the correct detection surface. */
        double agg_threshold = (double)engine->thresholds.syn_flood_threshold * 0.4;
        uint32_t min_syn_only = 5;  /* 4-node IWSN: >5 SYN-only flows is already DDoS */
        if ((sr > agg_threshold && targets[i].flow_count > 5) || (targets[i].syn_only_flows > min_syn_only && sor > 0.7)) {
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

    /*
     * IWSN-aware UDP flood discrimination (RFC 4732 §2.1)
     *
     * False-positive guard: MQTT runs over TCP, but other sensor protocols
     * (CoAP on UDP/5683, custom sensor payloads) produce short UDP bursts on
     * a FIXED destination port.  A genuine UDP flood aims to exhaust bandwidth
     * and typically scatters packets across MANY destination ports.
     *
     * Rule: only flag as a flood if the flow ALSO shows port diversity
     * (unique_dst_port_count > 5).  A single-port sensor burst — even at
     * high PPS — is not a volumetric flood, it is sensor data.
     */
    int is_port_diverse = (flow->unique_dst_port_count > 5);

    if (rate > engine->thresholds.udp_flood_threshold &&
        flow->total_packets > engine->thresholds.udp_flood_packet_count &&
        is_port_diverse) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_UDP_FLOOD; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "UDP Flood Attack");
        strncpy(detection->rfc_reference, "RFC 768, RFC 4732", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "UDP flood per RFC 4732: %.1f pkt/s across %u ports "
                "(IWSN threshold: %u pps, min pkts: %u)",
                rate, flow->unique_dst_port_count,
                engine->thresholds.udp_flood_threshold,
                engine->thresholds.udp_flood_packet_count);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port; detection->dst_port = flow->dst_port; detection->protocol = flow->protocol;
        detection->packet_count = flow->total_packets; detection->byte_count = flow->total_bytes;
        detection->packets_per_second = rate; detection->duration_seconds = duration; detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0, rate / (engine->thresholds.udp_flood_threshold * 2.0));
        snprintf(detection->details, sizeof(detection->details),
                "Packets:%lu Bytes:%lu Rate:%.1f UniqPorts:%u Duration:%.2fs",
                flow->total_packets, flow->total_bytes, rate,
                flow->unique_dst_port_count, duration);
        return 1;
    }
    return 0;
}

/* ========== HTTP Flood Detection (RFC 9110) ========== */
int detect_http_flood(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    /*
     * IWSN-aware HTTP flood detection (RFC 9110 §9.3.1)
     *
     * Port guard: IWSN controller runs on port 8765, not 80/8080.  Include
     * it alongside standard HTTP ports.  All three are TCP.
     *
     * Minimum packet count guard: Without it a 2-packet burst sampled over
     * a 0.1 s floor produces rate = 20 pps which exceeds threshold = 30.
     * Require at least 5 HTTP packets so the rate is measured over a
     * meaningful window (5 / 30 = 167 ms minimum before triggering).
     */
    int is_http = (flow->dst_port == 80 || flow->dst_port == 8080 ||
                   flow->dst_port == 8765 ||
                   strstr(flow->protocol_name, "HTTP") != NULL);
    if (!is_http || flow->protocol != IPPROTO_TCP) return 0;
    if (flow->total_packets < 5) return 0;
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

    /* Bug fix: minimum absolute packet count guard.
     * Without this, a 2-packet burst sampled at 0.1 s duration produces
     * rate = 20 pps which would fire above a threshold of 15.  Require at
     * least 10 ICMP packets so the measurement is over a statistically
     * meaningful window (>=10 / 15 pps = 667 ms minimum before triggering). */
    if (rate > engine->thresholds.icmp_flood_threshold &&
        flow->total_packets >= 10) {
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
    /*
     * RFC 791 §3.2: Maximum IP datagram total length is 65535 bytes.
     * Ping of Death sends crafted ICMP fragments that when reassembled
     * produce a datagram >= 65535 bytes, causing buffer overflow.
     * Use >= operator: a 65535-byte ICMP packet is the exact RFC maximum
     * and is always anomalous in an IWSN environment.
     */
    if (flow->max_packet_size >= engine->thresholds.pod_packet_size) {
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
    /*
     * RUDY (R-U-Dead-Yet) — RFC 9110 §6.3 slow POST body.
     *
     * IWSN port guard: add port 8765 (IWSN controller).
     * Connection guard: requires at least one established connection
     * (3-way handshake completed); eliminates SYN-only or RST flows that
     * share the same port but are not slow-POST sessions.
     * Rate interpretation: avg_rate is bytes/s for the entire flow
     * (headers + body). A real HTTP POST with a tiny body has a body rate
     * of ~0-2 B/s after the initial header exchange.  The 10 B/s threshold
     * is conservative enough to absorb header overhead.
     */
    int is_http = (flow->dst_port == 80 || flow->dst_port == 8080 ||
                   flow->dst_port == 8765 ||
                   strstr(flow->protocol_name, "HTTP") != NULL);
    if (!is_http || flow->protocol != IPPROTO_TCP) return 0;
    if (flow->total_packets < engine->thresholds.rudy_min_packets) return 0;
    if (flow->established_connections == 0) return 0;  /* no completed handshake */
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
    /* Bug fix: was using tcp_connect_scan_ports (connect-scan threshold) for
     * SYN scan detection.  SYN scan produces SYNs + RSTs but no completed
     * handshakes.  Use port_scan_unique_ports (the generic scan threshold)
     * which is calibrated to the IWSN's 8-port detection floor. */
    if (flow->syn_count > 5 && flow->rst_count > 0 && flow->ack_count < (flow->syn_count * 0.3)) {
        if (flow->unique_dst_port_count >= engine->thresholds.port_scan_unique_ports) {
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
        /*
         * Bug fix: the original ratio  ack_count / syn_count > 0.8  is wrong.
         *
         * In any TCP flow, ack_count >> syn_count because every packet after
         * the initial SYN carries the ACK flag (SYN-ACK, data, FIN-ACK).
         * Computing ack_count/syn_count always yields a ratio >> 1.0,
         * making it useless as a completion test.
         *
         * Correct RFC 793 §3.9 model:
         *  - Connect scan: scanner completes the 3-way handshake by sending
         *    an ACK after each SYN-ACK.  syn_ack_count tracks server SYN-ACKs
         *    (bidirectional flow).  If (ack_count - syn_ack_count) is large,
         *    the scanner is contributing its own ACKs, i.e. it is completing
         *    handshakes (connect scan).
         *  - SYN scan: scanner sends RST immediately after SYN-ACK; it never
         *    contributes its own ACKs so (ack_count - syn_ack_count) ≈ 0.
         *
         * scanner_acks = ack_count - syn_ack_count (server responses subtracted).
         * cr = scanner_acks / syn_count: fraction of probed ports where the
         * scanner sent a completing ACK.  threshold = tcp_connect_scan_completion.
         */
        int scanner_acks = (int)flow->ack_count - (int)flow->syn_ack_count;
        if (scanner_acks < 0) scanner_acks = 0;
        double cr = flow->syn_count > 0 ? (double)scanner_acks / (double)flow->syn_count : 0;
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
        /* Bug fix: add minimum packet count guard (same rationale as ICMP flood).
         * A 2-packet sample hitting 8 ports over 0.5 s is noise, not a scan.
         * Require at least 8 packets (one per threshold port) before firing. */
        if (avg_sz < 100 && flow->total_packets >= engine->thresholds.port_scan_unique_ports) {
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
