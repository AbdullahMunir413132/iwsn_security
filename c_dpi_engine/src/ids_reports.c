/*
 * IDS (Rule Engine) Detailed Report Generator
 * Generates comprehensive IDS/attack detection report
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "rule_engine.h"
#include "dpi_engine.h"

const char* get_attack_type_name(attack_type_t type) {
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
        default: return "Unknown";
    }
}

const char* get_severity_name(attack_severity_t severity) {
    switch(severity) {
        case SEVERITY_CRITICAL: return "CRITICAL";
        case SEVERITY_HIGH: return "HIGH";
        case SEVERITY_MEDIUM: return "MEDIUM";
        case SEVERITY_LOW: return "LOW";
        case SEVERITY_INFO: return "INFO";
        default: return "UNKNOWN";
    }
}

void generate_ids_report(rule_engine_t *engine, dpi_engine_t *dpi_engine, const char *output_file) {
    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", output_file);
        return;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(fp, "╔════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                          IDS (RULE ENGINE) DETAILED REPORT                                     ║\n");
    fprintf(fp, "║                              Generated: %s                                       ║\n", timestamp);
    fprintf(fp, "╚════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
    
    // ========== OVERVIEW SECTION ==========
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " DETECTION OVERVIEW\n");
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Total Flows Analyzed:     %u\n", dpi_engine->flow_count);
    fprintf(fp, "  Total Packets Analyzed:   %lu\n", engine->total_packets_analyzed);
    fprintf(fp, "  Attacks Detected:         %lu\n", engine->total_attacks_detected);
    fprintf(fp, "  Detection Rate:           %.2f%% of flows flagged\n", 
           dpi_engine->flow_count > 0 ? (engine->total_attacks_detected * 100.0 / dpi_engine->flow_count) : 0.0);
    fprintf(fp, "\n");
    
    // ========== ATTACK BREAKDOWN SECTION ==========
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " ATTACK TYPE BREAKDOWN\n");
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  %-25s : %lu\n", "SYN Flood Attacks", engine->attacks_by_type[ATTACK_SYN_FLOOD]);
    fprintf(fp, "  %-25s : %lu\n", "UDP Flood Attacks", engine->attacks_by_type[ATTACK_UDP_FLOOD]);
    fprintf(fp, "  %-25s : %lu\n", "HTTP Flood Attacks", engine->attacks_by_type[ATTACK_HTTP_FLOOD]);
    fprintf(fp, "  %-25s : %lu\n", "ICMP Flood Attacks", engine->attacks_by_type[ATTACK_ICMP_FLOOD]);
    fprintf(fp, "  %-25s : %lu\n", "Ping of Death", engine->attacks_by_type[ATTACK_PING_OF_DEATH]);
    fprintf(fp, "  %-25s : %lu\n", "TCP SYN Scan", engine->attacks_by_type[ATTACK_TCP_SYN_SCAN]);
    fprintf(fp, "  %-25s : %lu\n", "TCP Connect Scan", engine->attacks_by_type[ATTACK_TCP_CONNECT_SCAN]);
    fprintf(fp, "  %-25s : %lu\n", "UDP Scan", engine->attacks_by_type[ATTACK_UDP_SCAN]);
    fprintf(fp, "  %-25s : %lu\n", "Port Scans (Generic)", engine->attacks_by_type[ATTACK_PORT_SCAN_GENERIC]);
    fprintf(fp, "  %-25s : %lu\n", "ARP Spoofing", engine->attacks_by_type[ATTACK_ARP_SPOOFING]);
    fprintf(fp, "  %-25s : %lu\n", "RUDY (Slow POST)", engine->attacks_by_type[ATTACK_RUDY]);
    fprintf(fp, "\n");
    
    // ========== IP TRACKING SECTION ==========
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " IP ADDRESS TRACKING\n");
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Unique IPs Tracked:       %u\n", engine->ip_stats_count);
    fprintf(fp, "  Blocked IPs:              %u\n", engine->blocked_ip_count);
    // fprintf(fp, "  Blocked Packets:          %lu\n", engine->blocked_packet_count);
    fprintf(fp, "\n");
    
    if (engine->blocked_ip_count > 0) {
        fprintf(fp, "  Blocked IP Addresses:\n");
        for (uint32_t i = 0; i < engine->blocked_ip_count && i < 100; i++) {
            struct in_addr addr;
            addr.s_addr = htonl(engine->blocked_ips[i]);
            fprintf(fp, "    • %s\n", inet_ntoa(addr));
        }
        fprintf(fp, "\n");
    }
    
    // ========== DETECTION THRESHOLDS SECTION ==========
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " DETECTION THRESHOLDS CONFIGURATION\n");
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  SYN Flood:\n");
    fprintf(fp, "    Threshold:              %u packets/sec\n", engine->thresholds.syn_flood_threshold);
    fprintf(fp, "    SYN/ACK Ratio:          %.2f\n", engine->thresholds.syn_flood_ratio);
    fprintf(fp, "    Time Window:            %u seconds\n\n", engine->thresholds.syn_flood_time_window);
    
    fprintf(fp, "  UDP Flood:\n");
    fprintf(fp, "    Threshold:              %u packets/sec\n", engine->thresholds.udp_flood_threshold);
    fprintf(fp, "    Min Packet Count:       %u\n", engine->thresholds.udp_flood_packet_count);
    fprintf(fp, "    Time Window:            %u seconds\n\n", engine->thresholds.udp_flood_time_window);
    
    fprintf(fp, "  HTTP Flood:\n");
    fprintf(fp, "    Threshold:              %u requests/sec\n", engine->thresholds.http_flood_threshold);
    fprintf(fp, "    Time Window:            %u seconds\n\n", engine->thresholds.http_flood_time_window);
    
    fprintf(fp, "  Port Scans:\n");
    fprintf(fp, "    Unique Ports:           %u\n", engine->thresholds.port_scan_unique_ports);
    fprintf(fp, "    Connection Ratio:       %.2f\n", engine->thresholds.port_scan_connection_ratio);
    fprintf(fp, "    Time Window:            %u seconds\n\n", engine->thresholds.port_scan_time_window);
    
    fprintf(fp, "  ICMP Flood:\n");
    fprintf(fp, "    Threshold:              %u packets/sec\n", engine->thresholds.icmp_flood_threshold);
    fprintf(fp, "    Time Window:            %u seconds\n\n", engine->thresholds.icmp_flood_time_window);
    
    // ========== DETAILED ATTACK RECORDS SECTION ==========
    if (engine->total_attacks_detected > 0 && engine->detection_count > 0) {
        fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
        fprintf(fp, " DETAILED ATTACK RECORDS\n");
        fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n\n");
        
        uint32_t display_count = engine->detection_count < 1000 ? engine->detection_count : 1000;
        for (uint32_t i = 0; i < display_count; i++) {
            attack_detection_t *attack = &engine->detections[i];
            
            struct in_addr attacker, target;
            attacker.s_addr = htonl(attack->attacker_ip);
            target.s_addr = htonl(attack->target_ip);
            
            fprintf(fp, "┌─ Attack #%u ───────────────────────────────────────────────────────────────────────────────\n", i+1);
            fprintf(fp, "│\n");
            fprintf(fp, "│  Attack Type:         %s\n", attack->attack_name);
            fprintf(fp, "│  Severity:            %s\n", get_severity_name(attack->severity));
            fprintf(fp, "│  Confidence:          %.1f%%\n", attack->confidence_score * 100.0);
            fprintf(fp, "│\n");
            fprintf(fp, "│  Source:              %s:%u\n", inet_ntoa(attacker), attack->src_port);
            fprintf(fp, "│  Target:              %s:%u\n", inet_ntoa(target), attack->dst_port);
            fprintf(fp, "│  Protocol:            %u (%s)\n", attack->protocol,
                   attack->protocol == 6 ? "TCP" : attack->protocol == 17 ? "UDP" : attack->protocol == 1 ? "ICMP" : "Other");
            fprintf(fp, "│\n");
            fprintf(fp, "│  Metrics:\n");
            fprintf(fp, "│    Packets:           %lu\n", attack->packet_count);
            fprintf(fp, "│    Bytes:             %lu\n", attack->byte_count);
            fprintf(fp, "│    Packets/sec:       %.2f\n", attack->packets_per_second);
            fprintf(fp, "│    Duration:          %.3f seconds\n", attack->duration_seconds);
            fprintf(fp, "│\n");
            fprintf(fp, "│  Description:\n");
            fprintf(fp, "│    %s\n", attack->description);
            fprintf(fp, "│\n");
            fprintf(fp, "└────────────────────────────────────────────────────────────────────────────────────────────\n\n");
        }
        
        if (engine->detection_count > 1000) {
            fprintf(fp, "... and %u more attacks (display limited to 1000)\n\n",
                   engine->detection_count - 1000);
        }
    } else {
        fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
        fprintf(fp, " NO ATTACKS DETECTED\n");
        fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
        fprintf(fp, "  All analyzed traffic appears to be normal.\n");
        fprintf(fp, "  No suspicious patterns or attack signatures were found.\n\n");
    }
    
    // ========== STATISTICAL SUMMARY SECTION ==========
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, " FLOW ANALYSIS STATISTICS\n");
    fprintf(fp, "════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Total Flows:              %u\n", dpi_engine->flow_count);
    fprintf(fp, "  Analyzed Flows:           %u\n", dpi_engine->flow_count);
    fprintf(fp, "  Malicious Flows:          %lu (%.2f%%)\n", 
           engine->total_attacks_detected,
           dpi_engine->flow_count > 0 ? (engine->total_attacks_detected * 100.0 / dpi_engine->flow_count) : 0.0);
    fprintf(fp, "  Normal Flows:             %u (%.2f%%)\n",
           dpi_engine->flow_count - (uint32_t)engine->total_attacks_detected,
           dpi_engine->flow_count > 0 ? ((dpi_engine->flow_count - engine->total_attacks_detected) * 100.0 / dpi_engine->flow_count) : 0.0);
    fprintf(fp, "\n");
    
    // ========== END OF REPORT ==========
    fprintf(fp, "╔════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                                    END OF IDS REPORT                                           ║\n");
    fprintf(fp, "╚════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
    
    fclose(fp);
    printf("✓ IDS detailed report saved to: %s\n", output_file);
}
