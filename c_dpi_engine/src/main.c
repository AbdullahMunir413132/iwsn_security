/*
 * PCAP File Processing - Main Program
 * Reads PCAP files and processes packets through DPI engine
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/stat.h>
#include "dpi_engine.h"

/* ========== Print Engine Statistics ========== */

void print_engine_stats(const dpi_engine_t *engine) {
    printf("\n========================================\n");
    printf("DPI ENGINE STATISTICS\n");
    printf("========================================\n");
    printf("Total packets: %lu\n", engine->total_packets);
    printf("Total bytes: %lu\n", engine->total_bytes);
    printf("L2 parsed: %lu\n", engine->l2_parsed);
    printf("L3 parsed: %lu\n", engine->l3_parsed);
    printf("L4 parsed: %lu\n", engine->l4_parsed);
    printf("Flows created: %lu\n", engine->flows_created);
    printf("Active flows: %u\n", engine->flow_count);
    printf("========================================\n");
}

/* ========== Main Function ========== */

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        fprintf(stderr, "Example: %s ../pcap_samples/sample.pcap\n", argv[0]);
        return 1;
    }
    
    const char *pcap_file = argv[1];
    
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║              IWSN SECURITY - DPI ENGINE v2.0                   ║\n");
    printf("║          Complete Layer 2-5 + Partial Layer 7 Analysis        ║\n");
    printf("║                    Powered by nDPI                             ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // Initialize DPI engine
    dpi_engine_t *engine = dpi_engine_init(10000);  // Max 10k flows
    if (!engine) {
        fprintf(stderr, "Failed to initialize DPI engine\n");
        return 1;
    }
    
    // Process PCAP file (collect all data silently)
    pcap_stats_t pcap_stats;
    if (process_pcap_file(pcap_file, engine, &pcap_stats) != 0) {
        fprintf(stderr, "Failed to process PCAP file\n");
        dpi_engine_destroy(engine);
        return 1;
    }
    
    // ===== PHASE 1: PCAP SUMMARY =====
    print_pcap_summary(&pcap_stats);
    
    // ===== PHASE 2: FLOW-BY-FLOW ANALYSIS WITH PACKETS =====
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║            DETAILED FLOW-BY-FLOW ANALYSIS BEGINS               ║\n");
    printf("║                  Total Flows: %-5u                            ║\n", engine->flow_count);
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // Print each flow with all its packets
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        print_flow_with_packets(&engine->flows[i], i + 1);
    }
    
    // ===== PHASE 3: PROTOCOL DISTRIBUTION SUMMARY =====
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║                  PROTOCOL DISTRIBUTION SUMMARY                 ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Count protocols
    uint32_t protocol_counts[256] = {0};
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        const char *proto = engine->flows[i].protocol_name;
        if (strstr(proto, "SSH")) protocol_counts[0]++;
        else if (strstr(proto, "HTTP")) protocol_counts[1]++;
        else if (strstr(proto, "DNS")) protocol_counts[2]++;
        else if (strstr(proto, "MQTT")) protocol_counts[3]++;
        else if (strstr(proto, "TLS") || strstr(proto, "SSL")) protocol_counts[4]++;
        else if (strstr(proto, "FTP")) protocol_counts[5]++;
        else if (strstr(proto, "Unknown")) protocol_counts[255]++;
        else protocol_counts[6]++; // Other
    }
    
    if (protocol_counts[0] > 0) printf("  SSH:        %u flows\n", protocol_counts[0]);
    if (protocol_counts[1] > 0) printf("  HTTP:       %u flows\n", protocol_counts[1]);
    if (protocol_counts[2] > 0) printf("  DNS:        %u flows\n", protocol_counts[2]);
    if (protocol_counts[3] > 0) printf("  MQTT:       %u flows\n", protocol_counts[3]);
    if (protocol_counts[4] > 0) printf("  TLS/SSL:    %u flows\n", protocol_counts[4]);
    if (protocol_counts[5] > 0) printf("  FTP:        %u flows\n", protocol_counts[5]);
    if (protocol_counts[6] > 0) printf("  Other:      %u flows\n", protocol_counts[6]);
    if (protocol_counts[255] > 0) printf("  Unknown:    %u flows\n", protocol_counts[255]);
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    // Cleanup
    dpi_engine_destroy(engine);
    
    printf("\n✓ Analysis complete. DPI Engine terminated successfully.\n\n");
    
    return 0;
}
