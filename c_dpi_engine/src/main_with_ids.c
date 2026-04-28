/*
 * IWSN Security - Main Program with Integrated Intrusion Detection
 * Combines DPI Engine with Rule-Based Attack Detection
 * MQTT parsing happens AFTER attack detection for security
 * Supports both PCAP (offline) and Real-Time (live) capture modes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/stat.h>
#include "dpi_engine.h"
#include "rule_engine.h"
#include "mqtt_integration.h"
#include "live_capture.h"

static void live_ids_callback(void *rule_engine_ctx, const parsed_packet_t *packet) {
    if (rule_engine_ctx && packet) {
        rule_engine_analyze_packet((rule_engine_t *)rule_engine_ctx, packet);
    }
}

static int live_ids_is_blocked(void *rule_engine_ctx, uint32_t ip_address) {
    if (!rule_engine_ctx) {
        return 0;
    }
    return is_ip_blocked((rule_engine_t *)rule_engine_ctx, ip_address);
}

static void live_mqtt_callback(void *mqtt_ctx, parsed_packet_t *packet) {
    (void)mqtt_ctx;
    if (packet) {
        parse_mqtt_packet_secure(packet);
    }
}

/* ========== Process PCAP File with Attack Detection ========== */

int process_pcap_with_ids(const char *filename, dpi_engine_t *dpi_engine, 
                          rule_engine_t *rule_engine, pcap_stats_t *stats) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;
    uint32_t packet_count = 0;
    
    // Initialize stats
    memset(stats, 0, sizeof(pcap_stats_t));
    strncpy(stats->filename, filename, sizeof(stats->filename) - 1);
    stats->min_packet_size = 0xFFFFFFFF;
    stats->max_packet_size = 0;
    
    // Get file size
    struct stat st;
    if (stat(filename, &st) == 0) {
        stats->file_size = st.st_size;
    }
    
    printf("\n[PCAP] Opening file: %s\n", filename);
    
    // Open PCAP file
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[Error] Failed to open PCAP file: %s\n", errbuf);
        return -1;
    }
    
    // Get datalink type
    int datalink = pcap_datalink(handle);
    printf("[PCAP] Datalink type: %s\n", pcap_datalink_val_to_name(datalink));
    
    // Support Ethernet, Linux cooked capture v1 and v2
    if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL && datalink != DLT_LINUX_SLL2) {
        fprintf(stderr, "[Error] Unsupported datalink type: %s\n", pcap_datalink_val_to_name(datalink));
        fprintf(stderr, "[Info]  Supported: Ethernet (DLT_EN10MB), LINUX_SLL, LINUX_SLL2\n");
        pcap_close(handle);
        return -1;
    }
    
    // Store datalink type for proper L2 header parsing
    stats->datalink_type = datalink;
    dpi_engine->datalink_type = datalink;
    
    printf("[PCAP] Processing packets and analyzing for attacks...\n");
    
    // Read and process packets
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;  // Timeout
        
        packet_count++;
        
        // Safety limit: Stop if we've processed too many packets (likely massive flood)
        if (packet_count > 500000) {
            fprintf(stderr, "\n[Warning] Packet limit reached (500k) - stopping analysis\n");
            fprintf(stderr, "[Info] This is likely a massive DDoS attack - early stopping to save resources\n");
            break;
        }
        
        // Track timing
        if (packet_count == 1) {
            stats->start_time = header->ts;
        }
        stats->end_time = header->ts;
        
        // Parse packet with DPI engine
        parsed_packet_t parsed;
        if (parse_packet(dpi_engine, packet, header->caplen, header->ts, &parsed) == 0) {
            parsed.packet_number = packet_count;
            
            // ========== STEP 1: Analyze packet for attacks FIRST ==========
            rule_engine_analyze_packet(rule_engine, &parsed);
            
            // ========== STEP 2: Parse MQTT ONLY if packet is clean ==========
            // Check if this packet was flagged as part of an attack
            int is_attack_packet = 0;
            for (uint32_t i = 0; i < rule_engine->detection_count; i++) {
                attack_detection_t *det = &rule_engine->detections[i];
                if (det->attacker_ip == parsed.layer3.src_ip || 
                    det->target_ip == parsed.layer3.dst_ip) {
                    is_attack_packet = 1;
                    break;
                }
            }
            
            // Only parse MQTT for clean packets (security first!)
            if (!is_attack_packet) {
                parse_mqtt_packet_secure(&parsed);
            } else {
                // Attack packet - drop it (don't parse MQTT)
                printf("[SECURITY] Dropping attack packet from %u.%u.%u.%u\n",
                       (parsed.layer3.src_ip >> 24) & 0xFF,
                       (parsed.layer3.src_ip >> 16) & 0xFF,
                       (parsed.layer3.src_ip >> 8) & 0xFF,
                       parsed.layer3.src_ip & 0xFF);
            }
            
            // Store packet in flow AFTER MQTT parsing
            if (parsed.flow) {
                store_packet_in_flow(parsed.flow, &parsed);
            }
            
            // Update statistics
            stats->total_bytes += header->caplen;
            if (header->caplen < stats->min_packet_size) {
                stats->min_packet_size = header->caplen;
            }
            if (header->caplen > stats->max_packet_size) {
                stats->max_packet_size = header->caplen;
            }
            
            // Progress indicator and per-packet details (every 100 packets for readability)
            if (packet_count % 100 == 0) {
                printf("  [Packet %u] proto=%s src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u size=%u\n",
                       packet_count,
                       parsed.detected_protocol,
                       (parsed.layer3.src_ip >> 24) & 0xFF,
                       (parsed.layer3.src_ip >> 16) & 0xFF,
                       (parsed.layer3.src_ip >> 8) & 0xFF,
                       parsed.layer3.src_ip & 0xFF,
                       parsed.layer4.src_port,
                       (parsed.layer3.dst_ip >> 24) & 0xFF,
                       (parsed.layer3.dst_ip >> 16) & 0xFF,
                       (parsed.layer3.dst_ip >> 8) & 0xFF,
                       parsed.layer3.dst_ip & 0xFF,
                       parsed.layer4.dst_port,
                       header->caplen);
            }
            
            // Summary progress every 1000 packets
            if (packet_count % 1000 == 0) {
                printf("  \n--- Progress: %u packets, %u flows, %lu attacks detected ---\n\n", 
                       packet_count, dpi_engine->flow_count, 
                       rule_engine->total_attacks_detected);
                fflush(stdout);
            }
        }
    }
    
    if (res == -1) {
        fprintf(stderr, "[Error] Error reading packet: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    
    // Finalize statistics
    stats->total_packets = packet_count;
    stats->total_flows = dpi_engine->flow_count;
    if (stats->total_packets > 0) {
        stats->avg_packet_size = (double)stats->total_bytes / stats->total_packets;
    }
    stats->duration_seconds = (stats->end_time.tv_sec - stats->start_time.tv_sec) +
                              (stats->end_time.tv_usec - stats->start_time.tv_usec) / 1000000.0;
    
    printf("\n[PCAP] File processing complete\n");
    printf("[PCAP] Total packets: %u\n", packet_count);
    printf("[PCAP] Total flows: %u\n", dpi_engine->flow_count);
    
    pcap_close(handle);
    return 0;
}

/* ========== Main Function ========== */

int main(int argc, char *argv[]) {
    const char *pcap_file = NULL;
    const char *report_file = "attack_report.txt";
    capture_mode_t mode;
    
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║         IWSN SECURITY - DPI ENGINE + IDS v3.0                  ║\n");
    printf("║   Deep Packet Inspection + Intrusion Detection System         ║\n");
    printf("║                    Powered by nDPI                             ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // Determine mode from arguments or interactive prompt
    if (argc >= 2) {
        pcap_file = argv[1];
        report_file = (argc >= 3) ? argv[2] : "attack_report.txt";
        mode = CAPTURE_MODE_PCAP;
        printf("\n  [Mode] PCAP file provided via argument: %s\n", pcap_file);
    } else {
        mode = prompt_capture_mode();
        if (mode == CAPTURE_MODE_PCAP) {
            static char pcap_path[512];
            printf("  Enter PCAP file path: ");
            fflush(stdout);
            if (fgets(pcap_path, sizeof(pcap_path), stdin) == NULL) {
                fprintf(stderr, "Error reading input\n");
                return 1;
            }
            pcap_path[strcspn(pcap_path, "\n")] = '\0';
            if (strlen(pcap_path) == 0) {
                fprintf(stderr, "No file path provided.\n");
                return 1;
            }
            pcap_file = pcap_path;
        }
    }
    
    // Initialize DPI engine
    printf("\n[Step 1/4] Initializing DPI Engine...\n");
    dpi_engine_t *dpi_engine = dpi_engine_init(100000);  // Max 100k flows for DDoS scenarios
    if (!dpi_engine) {
        fprintf(stderr, "Failed to initialize DPI engine\n");
        return 1;
    }
    
    // Initialize Rule Engine (IDS)
    printf("\n[Step 2/4] Initializing Intrusion Detection System...\n");
    rule_engine_t *rule_engine = rule_engine_init();
    if (!rule_engine) {
        fprintf(stderr, "Failed to initialize Rule Engine\n");
        dpi_engine_destroy(dpi_engine);
        return 1;
    }
    
    pcap_stats_t pcap_stats;
    
    if (mode == CAPTURE_MODE_LIVE) {
        /* ========== LIVE CAPTURE MODE WITH IDS ========== */
        live_capture_config_t config;
        if (prompt_live_capture_config(&config) != 0) {
            fprintf(stderr, "Failed to configure live capture\n");
            rule_engine_destroy(rule_engine);
            dpi_engine_destroy(dpi_engine);
            return 1;
        }
        
        live_capture_ctx_t *ctx = live_capture_init(&config, dpi_engine);
        if (!ctx) {
            rule_engine_destroy(rule_engine);
            dpi_engine_destroy(dpi_engine);
            return 1;
        }
        
        // Enable IDS mode for real-time attack detection
        ctx->ids_mode = 1;
        ctx->rule_engine = rule_engine;
        ctx->ids_callback = live_ids_callback;
        ctx->ids_is_blocked_callback = live_ids_is_blocked;

        // Enable real-time MQTT parsing for clean packets in the capture loop
        ctx->mqtt_mode = 1;
        ctx->mqtt_context = NULL;
        ctx->mqtt_callback = live_mqtt_callback;
        
        printf("\n[Step 3/4] Starting real-time capture with IDS...\n");
        printf("[INFO] Packets will be analyzed for attacks in real-time\n\n");
        
        if (live_capture_start(ctx) != 0) {
            fprintf(stderr, "Live capture failed\n");
            live_capture_destroy(ctx);
            rule_engine_destroy(rule_engine);
            dpi_engine_destroy(dpi_engine);
            return 1;
        }
        
        // Print live capture summary
        live_capture_print_summary(ctx);
        
        // Copy stats for downstream reporting
        memcpy(&pcap_stats, &ctx->pcap_stats, sizeof(pcap_stats_t));
        
        live_capture_destroy(ctx);
        
    } else {
        /* ========== PCAP FILE MODE (Original) ========== */
        printf("\n[Step 3/4] Processing PCAP file with detailed packet analysis...\n");
        printf("[INFO] This will show per-packet DPI analysis and attack detection\n");
        if (process_pcap_with_ids(pcap_file, dpi_engine, rule_engine, &pcap_stats) != 0) {
            fprintf(stderr, "Failed to process PCAP file\n");
            rule_engine_destroy(rule_engine);
            dpi_engine_destroy(dpi_engine);
            return 1;
        }
    }
    
    // Analyze all flows for attack patterns (silent mode)
    printf("\n[Step 4/4] Performing deep flow analysis...\n");
    rule_engine_analyze_all_flows(rule_engine, dpi_engine);
    
    // ===== PRINT RESULTS =====
    
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║                   === ANALYSIS RESULTS ===                     ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    // ========== SECTION 1: DPI ENGINE RESULTS ==========
    printf("\n┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
    printf("┃                                                                ┃\n");
    printf("┃               [1] DPI ENGINE ANALYSIS RESULTS                  ┃\n");
    printf("┃                                                                ┃\n");
    printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n");
    
    // 1.1 PCAP Summary
    print_pcap_summary(&pcap_stats);
    
    // 1.2 Protocol Distribution
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║                  PROTOCOL DISTRIBUTION SUMMARY                 ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    uint32_t protocol_counts[256] = {0};
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        const char *proto = dpi_engine->flows[i].protocol_name;
        if (strstr(proto, "SSH")) protocol_counts[0]++;
        else if (strstr(proto, "HTTP")) protocol_counts[1]++;
        else if (strstr(proto, "DNS")) protocol_counts[2]++;
        else if (strstr(proto, "MQTT")) protocol_counts[3]++;
        else if (strstr(proto, "TLS") || strstr(proto, "SSL")) protocol_counts[4]++;
        else if (strstr(proto, "FTP")) protocol_counts[5]++;
        else if (strstr(proto, "Unknown")) protocol_counts[255]++;
        else protocol_counts[6]++;
    }
    
    if (protocol_counts[0] > 0) printf("  SSH:        %u flows\n", protocol_counts[0]);
    if (protocol_counts[1] > 0) printf("  HTTP:       %u flows\n", protocol_counts[1]);
    if (protocol_counts[2] > 0) printf("  DNS:        %u flows\n", protocol_counts[2]);
    if (protocol_counts[3] > 0) printf("  MQTT:       %u flows\n", protocol_counts[3]);
    if (protocol_counts[4] > 0) printf("  TLS/SSL:    %u flows\n", protocol_counts[4]);
    if (protocol_counts[5] > 0) printf("  FTP:        %u flows\n", protocol_counts[5]);
    if (protocol_counts[6] > 0) printf("  Other:      %u flows\n", protocol_counts[6]);
    if (protocol_counts[255] > 0) printf("  Unknown:    %u flows\n", protocol_counts[255]);
    
    printf("\n═══════════════════════════════════════════════════════════════\n");
    
    // 1.3 DETAILED FLOW-BY-FLOW ANALYSIS WITH ALL PACKETS
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║          DETAILED FLOW-BY-FLOW ANALYSIS BEGINS                 ║\n");
    printf("║              Total Flows: %-5u                                ║\n", dpi_engine->flow_count);
    printf("║          (Showing ALL flows with packet details)               ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    printf("\n[INFO] Printing detailed analysis for all %u flows...\n\n", dpi_engine->flow_count);
    
    // Print ALL flows with their packets
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        print_flow_with_packets(&dpi_engine->flows[i], i + 1);
        
        // Progress indicator for large captures
        if ((i + 1) % 100 == 0) {
            printf("\n[Progress] Printed %u / %u flows...\n\n", i + 1, dpi_engine->flow_count);
        }
    }
    
    printf("\n[INFO] Completed detailed flow analysis for all %u flows.\n", dpi_engine->flow_count);
    
    // ========== SECTION 2: RULE ENGINE (IDS) RESULTS ==========
    printf("\n\n");
    printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
    printf("┃                                                                ┃\n");
    printf("┃         [2] INTRUSION DETECTION SYSTEM (IDS) RESULTS          ┃\n");
    printf("┃                                                                ┃\n");
    printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n");
    
    // 2.1 Attack Detection Summary
    print_attack_summary(rule_engine);
    
    // 2.2 Detailed Attack Analysis (only if attacks detected)
    if (rule_engine->total_attacks_detected > 0) {
        print_detailed_attack_analysis(rule_engine);
        
        // Generate report file
        generate_attack_report(rule_engine, report_file);
    }
    
    // ========== SECTION 3: MQTT PARSER RESULTS ==========
    printf("\n\n");
    printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
    printf("┃                                                                ┃\n");
    printf("┃            [3] MQTT PROTOCOL ANALYSIS RESULTS                  ┃\n");
    printf("┃                                                                ┃\n");
    printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n");
    
    // 3.1 MQTT Protocol Statistics
    print_mqtt_statistics();
    
    printf("\n═══════════════════════════════════════════════════════════════\n");
    
    // Cleanup
    rule_engine_destroy(rule_engine);
    dpi_engine_destroy(dpi_engine);
    
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║  ✓ Analysis Complete - DPI Engine + IDS Terminated            ║\n");
    printf("║                                                                ║\n");
    if (rule_engine && rule_engine->total_attacks_detected > 0) {
        printf("║  ⚠️  ATTACKS DETECTED - See report: %-25s  ║\n", report_file);
    } else {
        printf("║  ✓ No Attacks Detected - Traffic Appears Normal               ║\n");
    }
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    return 0;
}
