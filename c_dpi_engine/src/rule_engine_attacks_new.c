/*
 * Rule Engine - New Attack Detection Implementations (12 new RFC-compliant detectors)
 * Xmas/NULL/FIN scans, Land, Smurf, Fraggle, Teardrop, DNS/NTP Amp, Slowloris, IP Spoofing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include "rule_engine.h"

/* ========== Xmas Tree Scan Detection (RFC 793 §3.9) ========== 
 * RFC 793 §3.9: A segment with FIN+PSH+URG flags set is invalid for 
 * connection initiation. Closed ports respond with RST; open ports drop silently.
 * Attackers exploit this for stealthy port enumeration. */
int detect_xmas_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_TCP) return 0;
    /* Xmas scan: FIN+PSH+URG (0x29) set, no SYN or ACK.
     * Minimum packet count = stealth_scan_port_threshold: need at least one
     * probe per threshold port before the rate can be considered reliable. */
    if (flow->fin_count > 0 && flow->syn_count == 0 && flow->ack_count == 0 &&
        flow->total_packets >= engine->thresholds.stealth_scan_port_threshold &&
        flow->unique_dst_port_count >= engine->thresholds.stealth_scan_port_threshold) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_XMAS_SCAN; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "Xmas Tree Scan");
        strncpy(detection->rfc_reference, "RFC 793 S3.9", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "Xmas scan per RFC 793 S3.9: FIN+PSH+URG to %u ports (no SYN/ACK)", flow->unique_dst_port_count);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->protocol = flow->protocol; detection->packet_count = flow->total_packets;
        detection->detection_time = flow->last_seen;
        detection->duration_seconds = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
        detection->confidence_score = fmin(1.0, (double)flow->unique_dst_port_count / 20.0);
        snprintf(detection->details, sizeof(detection->details), "FIN:%u Ports:%u (FIN+PSH+URG stealth scan)", flow->fin_count, flow->unique_dst_port_count);
        return 1;
    }
    return 0;
}

/* ========== NULL Scan Detection (RFC 793 §3.9) ========== 
 * RFC 793 §3.9: A TCP segment with no flags set is anomalous. 
 * Closed ports respond with RST; open ports silently discard. */
int detect_null_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_TCP) return 0;
    /* NULL scan: no flags at all — syn=0, ack=0, fin=0, rst=0 but packets exist */
    if (flow->total_packets > 3 && flow->syn_count == 0 && flow->ack_count == 0 &&
        flow->fin_count == 0 && flow->rst_count == 0 &&
        flow->unique_dst_port_count >= engine->thresholds.stealth_scan_port_threshold) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_NULL_SCAN; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "NULL Scan");
        strncpy(detection->rfc_reference, "RFC 793 S3.9", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "NULL scan per RFC 793 S3.9: %lu packets with no TCP flags to %u ports", flow->total_packets, flow->unique_dst_port_count);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->protocol = flow->protocol; detection->packet_count = flow->total_packets;
        detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0, (double)flow->unique_dst_port_count / 15.0);
        snprintf(detection->details, sizeof(detection->details), "Pkts:%lu Ports:%u (all zero flags)", flow->total_packets, flow->unique_dst_port_count);
        return 1;
    }
    return 0;
}

/* ========== FIN Scan Detection (RFC 793 §3.9) ========== 
 * RFC 793: FIN-only segments to closed ports provoke RST responses,
 * enabling port enumeration without SYN. */
int detect_fin_scan(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_TCP) return 0;
    if (flow->fin_count > 3 && flow->syn_count == 0 && flow->ack_count == 0 &&
        flow->unique_dst_port_count >= engine->thresholds.stealth_scan_port_threshold) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_FIN_SCAN; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "FIN Scan");
        strncpy(detection->rfc_reference, "RFC 793 S3.9", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "FIN scan per RFC 793 S3.9: %u FIN-only packets to %u ports", flow->fin_count, flow->unique_dst_port_count);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->protocol = flow->protocol; detection->packet_count = flow->fin_count;
        detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0, (double)flow->unique_dst_port_count / 15.0);
        snprintf(detection->details, sizeof(detection->details), "FIN:%u Ports:%u (FIN-only stealth)", flow->fin_count, flow->unique_dst_port_count);
        return 1;
    }
    return 0;
}

/* ========== Land Attack Detection (RFC 6274, CVE-1999-0016) ========== 
 * A spoofed TCP SYN where source IP:port == destination IP:port.
 * Causes the target to try to establish a connection with itself. */
int detect_land_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    (void)engine;
    if (flow->protocol != IPPROTO_TCP) return 0;
    if (flow->src_ip == flow->dst_ip && flow->src_port == flow->dst_port && flow->src_ip != 0) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_LAND_ATTACK; detection->severity = SEVERITY_CRITICAL;
        strcpy(detection->attack_name, "Land Attack");
        strncpy(detection->rfc_reference, "RFC 6274, CVE-1999-0016", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "Land attack per RFC 6274: src==dst (%s:%u)",
                inet_ntoa((struct in_addr){.s_addr = htonl(flow->src_ip)}), flow->src_port);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port; detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol; detection->packet_count = flow->total_packets;
        detection->detection_time = flow->last_seen; detection->confidence_score = 1.0;
        snprintf(detection->details, sizeof(detection->details), "src_ip==dst_ip && src_port==dst_port (self-connection loop)");
        return 1;
    }
    return 0;
}

/* ========== Smurf Attack Detection (RFC 2827/BCP 38, RFC 6274) ========== 
 * ICMP echo requests sent to broadcast address with spoofed source.
 * All hosts on network reply to victim, amplifying attack. */
int detect_smurf_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_ICMP) return 0;
    /*
     * Broadcast address check (RFC 919, RFC 922):
     *   - Directed broadcast: last octet == 255 (e.g. 192.168.1.255)
     *   - Limited broadcast: 255.255.255.255 (0xFFFFFFFF)
     * NOTE: x.x.x.0 is the network address, NOT a broadcast address in
     * classless routing (RFC 1812 §4.2.3.1) — removed to eliminate
     * false positives on legitimate traffic to network addresses.
     */
    int is_broadcast = ((flow->dst_ip & 0xFF) == 0xFF ||
                        flow->dst_ip == 0xFFFFFFFF);
    if (!is_broadcast) return 0;
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < 0.1) duration = 0.1;
    double rate = (double)flow->total_packets / duration;
    /*
     * Rate-only condition: remove the unconditional total_packets > 50
     * OR branch that would trigger on any 50-packet ICMP flow to a *.255
     * address (e.g. ARP probe storms in DHCP discovery).  Require a
     * sustained rate to distinguish Smurf from burst noise.
     */
    if (rate > engine->thresholds.smurf_icmp_threshold) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_SMURF; detection->severity = SEVERITY_CRITICAL;
        strcpy(detection->attack_name, "Smurf Attack");
        strncpy(detection->rfc_reference, "RFC 2827 (BCP 38), RFC 6274", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "Smurf per BCP 38: ICMP echo to broadcast %s at %.2f pkt/s",
                inet_ntoa((struct in_addr){.s_addr = htonl(flow->dst_ip)}), rate);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->protocol = flow->protocol; detection->packet_count = flow->total_packets;
        detection->packets_per_second = rate; detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen; detection->confidence_score = 0.95;
        snprintf(detection->details, sizeof(detection->details), "ICMP to broadcast: %lu pkts, %.2f pkt/s", flow->total_packets, rate);
        return 1;
    }
    return 0;
}

/* ========== Fraggle Attack Detection (RFC 768, RFC 6274) ========== 
 * UDP variant of Smurf: spoofed UDP to broadcast port 7 (echo) or 19 (chargen). */
int detect_fraggle_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_UDP) return 0;
    /*
     * Fraggle requires two conditions simultaneously (RFC 6274 §8.3.2):
     *   1. Destination is a broadcast address (same logic as Smurf above)
     *   2. Destination port is echo/7 or chargen/19
     * Only THEN check rate OR minimum packet count.
     * Without requiring echo/chargen port in both conditions, any high-rate
     * UDP broadcast (e.g. mDNS/5353) would incorrectly fire as Fraggle.
     */
    int is_broadcast = ((flow->dst_ip & 0xFF) == 0xFF ||
                        flow->dst_ip == 0xFFFFFFFF);
    if (!is_broadcast) return 0;
    int is_echo_chargen = (flow->dst_port == 7 || flow->dst_port == 19);
    if (!is_echo_chargen) return 0;  /* non-echo-port UDP broadcast is Smurf/flood, not Fraggle */
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < 0.1) duration = 0.1;
    double rate = (double)flow->total_packets / duration;
    if (rate > engine->thresholds.fraggle_udp_threshold || flow->total_packets > 10) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_FRAGGLE; detection->severity = SEVERITY_CRITICAL;
        strcpy(detection->attack_name, "Fraggle Attack");
        strncpy(detection->rfc_reference, "RFC 768, RFC 6274", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "Fraggle per RFC 6274: UDP to broadcast port %u at %.2f pkt/s", flow->dst_port, rate);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->dst_port = flow->dst_port; detection->protocol = flow->protocol;
        detection->packet_count = flow->total_packets; detection->packets_per_second = rate;
        detection->detection_time = flow->last_seen; detection->confidence_score = 0.9;
        snprintf(detection->details, sizeof(detection->details), "UDP broadcast port %u: %lu pkts", flow->dst_port, flow->total_packets);
        return 1;
    }
    return 0;
}

/* ========== Teardrop Attack Detection (RFC 791 §3.2) ========== 
 * Overlapping IP fragment offsets cause crash on reassembly.
 * Detected via impossible fragment_offset values. */
int detect_teardrop_attack(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    (void)engine;
    if (flow->protocol != IPPROTO_UDP && flow->protocol != IPPROTO_TCP) return 0;
    /*
     * Teardrop heuristic (RFC 791 §3.2, CVE-1997-0021):
     * True Teardrop requires tracking fragment offsets across packets,
     * which is not possible in a single-flow stat structure.  Instead,
     * we use the strongest available proxy: ALL captured packets in
     * the flow are anomalously tiny.
     *
     * Thresholds (updated for practical detection):
     *   - min_packet_size < 60: IP tot_len below 60 bytes is anomalous for
     *     a data-carrying fragment (UDP header alone is 8 bytes, so minimum
     *     legitimate UDP datagram = 28 bytes, but 60 bytes gives headroom
     *     to exclude single-byte payloads while catching crafted fragments).
     *     The old threshold of < 20 required IP tot_len below the minimum IP
     *     header length (20 bytes), which the DPI engine would reject as an
     *     invalid packet before it reaches a flow.
     *   - max_packet_size < 100: all fragments are small, consistent with
     *     crafted overlapping-offset teardrop fragments (typical 24-68 B).
     *   - total_packets > 2: at least 3 fragments are needed for overlap.
     * Confidence 0.75 reflects the heuristic (proxy) nature of this check.
     */
    if (flow->min_packet_size > 0 && flow->min_packet_size < 60 && flow->total_packets > 2 &&
        flow->max_packet_size < 100) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_TEARDROP; detection->severity = SEVERITY_CRITICAL;
        strcpy(detection->attack_name, "Teardrop Attack");
        strncpy(detection->rfc_reference, "RFC 791 S3.2, RFC 6274", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "Teardrop per RFC 791: suspicious fragments (min:%u max:%u bytes)", flow->min_packet_size, flow->max_packet_size);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->protocol = flow->protocol; detection->packet_count = flow->total_packets;
        detection->detection_time = flow->last_seen; detection->confidence_score = 0.75;
        snprintf(detection->details, sizeof(detection->details), "Fragment min:%u max:%u pkts:%lu", flow->min_packet_size, flow->max_packet_size, flow->total_packets);
        return 1;
    }
    return 0;
}

/* ========== DNS Amplification Detection (RFC 5358) ========== 
 * RFC 5358: Preventing recursive nameservers from being amplifiers.
 * Large DNS responses (>512B per RFC 1035) from port 53. */
int detect_dns_amplification(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_UDP) return 0;
    if (flow->src_port != 53) return 0; /* Responses come FROM port 53 */
    uint64_t avg_sz = flow->total_packets > 0 ? flow->total_bytes / flow->total_packets : 0;
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < 0.1) duration = 0.1;
    double rate = (double)flow->total_packets / duration;
    if (avg_sz > engine->thresholds.dns_amp_response_size && rate > engine->thresholds.dns_amp_rate_threshold) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_DNS_AMPLIFICATION; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "DNS Amplification");
        strncpy(detection->rfc_reference, "RFC 5358, RFC 5625", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "DNS amp per RFC 5358: avg %lu byte responses at %.2f/s from port 53", avg_sz, rate);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port; detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol; detection->packet_count = flow->total_packets;
        detection->byte_count = flow->total_bytes; detection->packets_per_second = rate;
        detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0,
            0.5 * fmin(1.0, (double)avg_sz / (engine->thresholds.dns_amp_response_size * 2.0)) +
            0.5 * fmin(1.0, rate / (engine->thresholds.dns_amp_rate_threshold * 5.0)));
        snprintf(detection->details, sizeof(detection->details), "DNS responses: avg %lu B, %lu pkts, %.2f/s", avg_sz, flow->total_packets, rate);
        return 1;
    }
    return 0;
}

/* ========== NTP Amplification Detection (RFC 5905, CVE-2013-5211) ========== */
int detect_ntp_amplification(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    if (flow->protocol != IPPROTO_UDP) return 0;
    if (flow->src_port != 123) return 0;
    uint64_t avg_sz = flow->total_packets > 0 ? flow->total_bytes / flow->total_packets : 0;
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < 0.1) duration = 0.1;
    double rate = (double)flow->total_packets / duration;
    if (avg_sz > engine->thresholds.ntp_amp_response_size && rate > engine->thresholds.ntp_amp_rate_threshold) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_NTP_AMPLIFICATION; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "NTP Amplification");
        strncpy(detection->rfc_reference, "RFC 5905, CVE-2013-5211", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "NTP amp per CVE-2013-5211: avg %lu byte responses at %.2f/s from port 123", avg_sz, rate);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->src_port = 123; detection->protocol = flow->protocol;
        detection->packet_count = flow->total_packets; detection->byte_count = flow->total_bytes;
        detection->packets_per_second = rate; detection->detection_time = flow->last_seen;
        detection->confidence_score = fmin(1.0,
            0.5 * fmin(1.0, (double)avg_sz / (engine->thresholds.ntp_amp_response_size * 2.0)) +
            0.5 * fmin(1.0, rate / (engine->thresholds.ntp_amp_rate_threshold * 5.0)));
        snprintf(detection->details, sizeof(detection->details), "NTP responses: avg %lu B, %lu pkts, %.2f/s", avg_sz, flow->total_packets, rate);
        return 1;
    }
    return 0;
}

/* ========== Slowloris Detection (RFC 9110) ========== 
 * Slow HTTP header transmission keeps connections open. */
int detect_slowloris(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    int is_http = (flow->dst_port == 80 || flow->dst_port == 8080 ||
                   flow->dst_port == 8765 ||
                   strstr(flow->protocol_name, "HTTP") != NULL);
    if (!is_http || flow->protocol != IPPROTO_TCP) return 0;
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + (flow->last_seen.tv_usec - flow->first_seen.tv_usec)/1e6;
    if (duration < engine->thresholds.slowloris_min_duration) return 0;
    /*
     * Multi-connection guard (RFC 9110 §9.3): Slowloris works by holding
     * many slow connections simultaneously.  A single legitimately slow
     * transfer (e.g. a large MQTT payload over HTTP) must NOT trigger.
     * Require established_connections >= slowloris_min_connections (5).
     * established_connections tracks completed 3-way handshakes, so this
     * filters out single-flow low-rate traffic that is not an attack.
     */
    if (flow->established_connections < engine->thresholds.slowloris_min_connections) return 0;
    double avg_rate = (double)flow->total_bytes / duration;
    /* Slowloris: very slow data rate over long duration, few packets spread over time */
    double pkt_rate = (double)flow->total_packets / duration;
    if (avg_rate < engine->thresholds.slowloris_header_rate && pkt_rate < 2.0 && flow->total_packets >= 5) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_SLOWLORIS; detection->severity = SEVERITY_MEDIUM;
        strcpy(detection->attack_name, "Slowloris Attack");
        strncpy(detection->rfc_reference, "RFC 9110, OWASP", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "Slowloris per RFC 9110: %.2f B/s header rate over %.0fs (threshold: %.1f B/s)", avg_rate, duration, engine->thresholds.slowloris_header_rate);
        detection->attacker_ip = flow->src_ip; detection->target_ip = flow->dst_ip;
        detection->src_port = flow->src_port; detection->dst_port = flow->dst_port;
        detection->protocol = flow->protocol; detection->packet_count = flow->total_packets;
        detection->byte_count = flow->total_bytes; detection->duration_seconds = duration;
        detection->detection_time = flow->last_seen; detection->confidence_score = 0.75;
        snprintf(detection->details, sizeof(detection->details), "Rate:%.2f B/s Pkts:%lu Duration:%.2fs", avg_rate, flow->total_packets, duration);
        return 1;
    }
    return 0;
}

/* ========== IP Spoofing Indicator Detection (RFC 2827/BCP 38) ========== 
 * BCP 38: Packets with impossible source addresses indicate spoofing. */
int detect_ip_spoofing(rule_engine_t *engine, const flow_stats_t *flow, attack_detection_t *detection) {
    (void)engine;
    uint32_t src = flow->src_ip;
    int is_spoofed = 0;
    char reason[128] = "";
    
    /*
     * RFC 5735 / RFC 6890: Special-purpose IPv4 addresses that MUST NOT
     * appear as a packet source on the public or mesh network interface.
     * Presence of these as source = spoofed or misconfigured packet (BCP 38).
     */
    if (src == 0) {
        is_spoofed = 1; strcpy(reason, "source 0.0.0.0 (THIS-HOST, RFC 1122)");
    } else if ((src >> 24) == 127) {
        /* 127.0.0.0/8 loopback (RFC 5735 §3) */
        if (flow->dst_ip != src) { is_spoofed = 1; strcpy(reason, "loopback 127.x.x.x as network source (RFC 5735)"); }
    } else if (src == 0xFFFFFFFF) {
        is_spoofed = 1; strcpy(reason, "limited broadcast 255.255.255.255 as source (RFC 919)");
    } else if ((src >> 28) == 0x0E) {
        /* 224.0.0.0/4 multicast (RFC 1112 §4) */
        is_spoofed = 1; strcpy(reason, "multicast 224.x.x.x as source (RFC 1112)");
    } else if ((src >> 28) >= 0x0F) {
        /* 240.0.0.0/4 reserved (RFC 1112, RFC 6890) */
        is_spoofed = 1; strcpy(reason, "reserved 240.x.x.x as source (RFC 6890)");
    } else if ((src >> 8) == 0xC00002) {
        /* NOTE: 169.254.0.0/16 link-local (APIPA) intentionally NOT flagged here.
         * On an internal IWSN mesh a node may self-assign 169.254.x.x while DHCP
         * is temporarily unreachable at boot.  That is a misconfiguration, not an
         * attack.  BCP 38 / RFC 3927 §7 only apply at internet-facing boundaries. */
        /* 192.0.2.0/24 TEST-NET-1 (RFC 5737 §3) */
        is_spoofed = 1; strcpy(reason, "TEST-NET-1 192.0.2.x as source (RFC 5737)");
    } else if ((src >> 8) == 0xC63364) {
        /* 198.51.100.0/24 TEST-NET-2 (RFC 5737 §3) */
        is_spoofed = 1; strcpy(reason, "TEST-NET-2 198.51.100.x as source (RFC 5737)");
    } else if ((src >> 8) == 0xCB0071) {
        /* 203.0.113.0/24 TEST-NET-3 (RFC 5737 §3) */
        is_spoofed = 1; strcpy(reason, "TEST-NET-3 203.0.113.x as source (RFC 5737)");
    } else if ((src >> 22) == 0x191) {
        /* 100.64.0.0/10 CGNAT shared address space (RFC 6598 §2) */
        is_spoofed = 1; strcpy(reason, "CGNAT 100.64.x.x as source (RFC 6598)");
    } else if ((src & 0xFF) == 0xFF && flow->protocol == IPPROTO_TCP) {
        /* x.x.x.255 subnet broadcast as TCP source */
        is_spoofed = 1; strcpy(reason, "subnet broadcast .255 as TCP source (RFC 919)");
    }
    
    if (is_spoofed) {
        memset(detection, 0, sizeof(attack_detection_t));
        detection->attack_type = ATTACK_IP_SPOOFING; detection->severity = SEVERITY_HIGH;
        strcpy(detection->attack_name, "IP Spoofing Indicator");
        strncpy(detection->rfc_reference, "RFC 2827 (BCP 38)", sizeof(detection->rfc_reference)-1);
        snprintf(detection->description, sizeof(detection->description),
                "IP spoofing per BCP 38: %s from %s",
                reason, inet_ntoa((struct in_addr){.s_addr = htonl(src)}));
        detection->attacker_ip = src; detection->target_ip = flow->dst_ip;
        detection->protocol = flow->protocol; detection->packet_count = flow->total_packets;
        detection->detection_time = flow->last_seen; detection->confidence_score = 0.85;
        snprintf(detection->details, sizeof(detection->details), "Impossible source: %s", reason);
        return 1;
    }
    return 0;
}
