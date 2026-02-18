/*
 * Rule Engine - Reporting Functions
 * Generate comprehensive attack reports and summaries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "rule_engine.h"

/* ========== Helper Functions ========== */

static void print_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    printf("%s", inet_ntoa(addr));
}

static void format_ip(uint32_t ip, char *buffer, size_t size) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    snprintf(buffer, size, "%s", inet_ntoa(addr));
}

/* ========== Single Attack Detection Print ========== */

void print_attack_detection(const attack_detection_t *detection) {
    const char *color = get_severity_color(detection->severity);
    const char *reset = "\033[0m";
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  %s⚠️  ATTACK DETECTED - %s%s\n", 
           color, severity_to_string(detection->severity), reset);
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    printf("\n[ATTACK INFORMATION]\n");
    printf("  Attack Type:     %s%s%s\n", color, detection->attack_name, reset);
    printf("  Description:     %s\n", detection->description);
    printf("  Confidence:      %.2f%%\n", detection->confidence_score * 100.0);
    
    printf("\n[SOURCE & TARGET]\n");
    printf("  Attacker IP:     ");
    print_ip(detection->attacker_ip);
    printf(":%u\n", detection->src_port);
    
    printf("  Target IP:       ");
    print_ip(detection->target_ip);
    printf(":%u\n", detection->dst_port);
    
    if (detection->protocol > 0) {
        printf("  Protocol:        ");
        if (detection->protocol == IPPROTO_TCP) printf("TCP (6)");
        else if (detection->protocol == IPPROTO_UDP) printf("UDP (17)");
        else if (detection->protocol == IPPROTO_ICMP) printf("ICMP (1)");
        else printf("%u", detection->protocol);
        printf("\n");
    }
    
    printf("\n[ATTACK METRICS]\n");
    printf("  Packet Count:    %lu packets\n", detection->packet_count);
    if (detection->byte_count > 0) {
        printf("  Byte Count:      %lu bytes (%.2f KB)\n", 
               detection->byte_count, detection->byte_count / 1024.0);
    }
    if (detection->packets_per_second > 0) {
        printf("  Packet Rate:     %.2f packets/second\n", detection->packets_per_second);
    }
    if (detection->duration_seconds > 0) {
        printf("  Duration:        %.2f seconds\n", detection->duration_seconds);
    }
    
    printf("\n[ADDITIONAL DETAILS]\n");
    printf("  %s\n", detection->details);
    
    printf("\n[DETECTION TIME]\n");
    char time_buf[64];
    struct tm *tm_info = localtime(&detection->detection_time.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("  Timestamp:       %s.%06ld\n", time_buf, detection->detection_time.tv_usec);
    
    printf("\n═══════════════════════════════════════════════════════════════\n");
}

/* ========== Attack Summary Print ========== */

void print_attack_summary(const rule_engine_t *engine) {
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║              INTRUSION DETECTION SUMMARY REPORT                ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    printf("\n[ANALYSIS OVERVIEW]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total Packets Analyzed:    %lu\n", engine->total_packets_analyzed);
    printf("  Total Attacks Detected:    %lu\n", engine->total_attacks_detected);
    printf("  Unique IP Addresses:       %u\n", engine->ip_stats_count);
    
    if (engine->total_attacks_detected == 0) {
        printf("\n  ✓ No attacks detected. Traffic appears normal.\n");
        printf("\n═══════════════════════════════════════════════════════════════\n");
        return;
    }
    
    printf("\n[ATTACKS BY TYPE]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    typedef struct {
        attack_type_t type;
        const char *name;
    } attack_info_t;
    
    attack_info_t attack_types[] = {
        {ATTACK_SYN_FLOOD, "SYN Flood"},
        {ATTACK_UDP_FLOOD, "UDP Flood"},
        {ATTACK_HTTP_FLOOD, "HTTP Flood"},
        {ATTACK_PING_OF_DEATH, "Ping of Death"},
        {ATTACK_ARP_SPOOFING, "ARP Spoofing"},
        {ATTACK_RUDY, "RUDY (Slow POST)"},
        {ATTACK_TCP_SYN_SCAN, "TCP SYN Scan"},
        {ATTACK_TCP_CONNECT_SCAN, "TCP Connect Scan"},
        {ATTACK_UDP_SCAN, "UDP Scan"},
        {ATTACK_ICMP_FLOOD, "ICMP Flood"},
        {ATTACK_PORT_SCAN_GENERIC, "Generic Port Scan"}
    };
    
    int attack_count = sizeof(attack_types) / sizeof(attack_types[0]);
    for (int i = 0; i < attack_count; i++) {
        if (engine->attacks_by_type[attack_types[i].type] > 0) {
            printf("  %-25s : %lu\n", 
                   attack_types[i].name, 
                   engine->attacks_by_type[attack_types[i].type]);
        }
    }
    
    printf("\n[SEVERITY DISTRIBUTION]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    uint32_t severity_counts[5] = {0};
    for (uint32_t i = 0; i < engine->detection_count; i++) {
        severity_counts[engine->detections[i].severity]++;
    }
    
    if (severity_counts[SEVERITY_CRITICAL] > 0) {
        printf("  🔴 CRITICAL : %u\n", severity_counts[SEVERITY_CRITICAL]);
    }
    if (severity_counts[SEVERITY_HIGH] > 0) {
        printf("  🟠 HIGH     : %u\n", severity_counts[SEVERITY_HIGH]);
    }
    if (severity_counts[SEVERITY_MEDIUM] > 0) {
        printf("  🟡 MEDIUM   : %u\n", severity_counts[SEVERITY_MEDIUM]);
    }
    if (severity_counts[SEVERITY_LOW] > 0) {
        printf("  🟢 LOW      : %u\n", severity_counts[SEVERITY_LOW]);
    }
    if (severity_counts[SEVERITY_INFO] > 0) {
        printf("  ⚪ INFO     : %u\n", severity_counts[SEVERITY_INFO]);
    }
    
    printf("\n[TOP ATTACKERS]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    // Count attacks per source IP
    typedef struct {
        uint32_t ip;
        uint32_t count;
    } attacker_count_t;
    
    attacker_count_t attackers[1000];
    uint32_t attacker_count = 0;
    
    for (uint32_t i = 0; i < engine->detection_count && attacker_count < 1000; i++) {
        uint32_t ip = engine->detections[i].attacker_ip;
        int found = 0;
        
        for (uint32_t j = 0; j < attacker_count; j++) {
            if (attackers[j].ip == ip) {
                attackers[j].count++;
                found = 1;
                break;
            }
        }
        
        if (!found) {
            attackers[attacker_count].ip = ip;
            attackers[attacker_count].count = 1;
            attacker_count++;
        }
    }
    
    // Simple bubble sort for top 10
    for (uint32_t i = 0; i < attacker_count - 1; i++) {
        for (uint32_t j = 0; j < attacker_count - i - 1; j++) {
            if (attackers[j].count < attackers[j + 1].count) {
                attacker_count_t temp = attackers[j];
                attackers[j] = attackers[j + 1];
                attackers[j + 1] = temp;
            }
        }
    }
    
    // Print top 10 attackers
    uint32_t display_count = (attacker_count < 10) ? attacker_count : 10;
    for (uint32_t i = 0; i < display_count; i++) {
        printf("  %2u. ", i + 1);
        print_ip(attackers[i].ip);
        printf(" - %u attacks\n", attackers[i].count);
    }
    
    printf("\n═══════════════════════════════════════════════════════════════\n");
}

/* ========== Detailed Attack Analysis ========== */

void print_detailed_attack_analysis(const rule_engine_t *engine) {
    if (engine->detection_count == 0) {
        return;
    }
    
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║              DETAILED ATTACK-BY-ATTACK ANALYSIS                ║\n");
    printf("║                  Total Detections: %-5u                       ║\n", 
           engine->detection_count);
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    for (uint32_t i = 0; i < engine->detection_count; i++) {
        printf("\n\n");
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf("                    ATTACK #%u of %u\n", i + 1, engine->detection_count);
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        
        print_attack_detection(&engine->detections[i]);
    }
}

/* ========== Generate Text Report File ========== */

void generate_attack_report(const rule_engine_t *engine, const char *output_file) {
    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "[Rule Engine] Failed to create report file: %s\n", output_file);
        return;
    }
    
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  IWSN SECURITY - INTRUSION DETECTION REPORT\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n\n");
    
    time_t now = time(NULL);
    fprintf(fp, "Report Generated: %s\n", ctime(&now));
    
    fprintf(fp, "\n[SUMMARY]\n");
    fprintf(fp, "Total Packets Analyzed: %lu\n", engine->total_packets_analyzed);
    fprintf(fp, "Total Attacks Detected: %lu\n", engine->total_attacks_detected);
    fprintf(fp, "Unique IP Addresses: %u\n\n", engine->ip_stats_count);
    
    if (engine->total_attacks_detected == 0) {
        fprintf(fp, "No attacks detected. Traffic appears normal.\n");
        fclose(fp);
        printf("[Rule Engine] Report generated: %s\n", output_file);
        return;
    }
    
    fprintf(fp, "\n[ATTACKS BY TYPE]\n");
    fprintf(fp, "─────────────────────────────────────────────────────────────\n");
    
    const char *attack_names[] = {
        "None", "SYN Flood", "UDP Flood", "HTTP Flood", "Ping of Death",
        "ARP Spoofing", "RUDY", "TCP SYN Scan", "TCP Connect Scan", 
        "UDP Scan", "Port Scan", "ICMP Flood"
    };
    
    for (int i = 1; i <= ATTACK_ICMP_FLOOD; i++) {
        if (engine->attacks_by_type[i] > 0) {
            fprintf(fp, "%-25s : %lu\n", attack_names[i], engine->attacks_by_type[i]);
        }
    }
    
    fprintf(fp, "\n[DETAILED DETECTIONS]\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n\n");
    
    for (uint32_t i = 0; i < engine->detection_count; i++) {
        const attack_detection_t *d = &engine->detections[i];
        
        fprintf(fp, "\n--- Attack #%u ---\n", i + 1);
        fprintf(fp, "Type: %s\n", d->attack_name);
        fprintf(fp, "Severity: %s\n", severity_to_string(d->severity));
        fprintf(fp, "Confidence: %.2f%%\n", d->confidence_score * 100.0);
        fprintf(fp, "Description: %s\n", d->description);
        
        char src_ip[32], dst_ip[32];
        format_ip(d->attacker_ip, src_ip, sizeof(src_ip));
        format_ip(d->target_ip, dst_ip, sizeof(dst_ip));
        
        fprintf(fp, "Attacker: %s:%u\n", src_ip, d->src_port);
        fprintf(fp, "Target: %s:%u\n", dst_ip, d->dst_port);
        fprintf(fp, "Packets: %lu, Bytes: %lu\n", d->packet_count, d->byte_count);
        
        if (d->packets_per_second > 0) {
            fprintf(fp, "Rate: %.2f packets/sec\n", d->packets_per_second);
        }
        if (d->duration_seconds > 0) {
            fprintf(fp, "Duration: %.2f seconds\n", d->duration_seconds);
        }
        
        fprintf(fp, "Details: %s\n", d->details);
        fprintf(fp, "\n");
    }
    
    fprintf(fp, "\n═══════════════════════════════════════════════════════════════\n");
    fprintf(fp, "End of Report\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n");
    
    fclose(fp);
    printf("[Rule Engine] Report generated successfully: %s\n", output_file);
}
