/*
 * PCAP Utilities - Shared functions for PCAP processing
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/stat.h>
#include "dpi_engine.h"

int process_pcap_file(const char *filename, dpi_engine_t *engine, pcap_stats_t *stats) {
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
    
    // Support both Ethernet and Linux cooked capture formats
    if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL && datalink != DLT_LINUX_SLL2) {
        fprintf(stderr, "[Error] Unsupported datalink type. Only Ethernet, LINUX_SLL, and LINUX_SLL2 are supported\n");
        pcap_close(handle);
        return -1;
    }
    
    // Store datalink type for later use
    stats->datalink_type = datalink;
    engine->datalink_type = datalink;  // Pass to engine for packet parsing
    
    printf("[PCAP] Processing packets (silent mode - collecting data)...\n");
    
    // Read and process packets (silent processing)
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) {
            // Timeout
            continue;
        }
        
        packet_count++;
        
        // Track first and last packet times
        if (packet_count == 1) {
            stats->start_time = header->ts;
        }
        stats->end_time = header->ts;
        
        // Parse packet
        parsed_packet_t parsed;
        if (parse_packet(engine, packet, header->caplen, header->ts, &parsed) == 0) {
            // Set packet number
            parsed.packet_number = packet_count;
            
            // Store packet in its flow for later detailed analysis
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
            
            // Progress indicator every 1000 packets
            if (packet_count % 1000 == 0) {
                printf("  ... processed %u packets, %u flows detected\r", 
                       packet_count, engine->flow_count);
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
    stats->total_flows = engine->flow_count;
    if (stats->total_packets > 0) {
        stats->avg_packet_size = (double)stats->total_bytes / stats->total_packets;
    }
    stats->duration_seconds = (stats->end_time.tv_sec - stats->start_time.tv_sec) +
                              (stats->end_time.tv_usec - stats->start_time.tv_usec) / 1000000.0;
    
    printf("\n[PCAP] File processing complete\n");
    printf("[PCAP] Total packets: %u\n", packet_count);
    printf("[PCAP] Total flows: %u\n", engine->flow_count);
    
    pcap_close(handle);
    return 0;
}

void print_pcap_summary(const pcap_stats_t *stats) {
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║              PCAP FILE DETAILED ANALYSIS SUMMARY               ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    printf("[FILE INFORMATION]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Filename:        %s\n", stats->filename);
    printf("  File Size:       %lu bytes (%.2f KB, %.2f MB)\n", 
           stats->file_size, 
           stats->file_size / 1024.0,
           stats->file_size / (1024.0 * 1024.0));
    
    printf("\n[CAPTURE TIMING]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    char start_time_str[128], end_time_str[128];
    format_timestamp(&stats->start_time, start_time_str, sizeof(start_time_str));
    format_timestamp(&stats->end_time, end_time_str, sizeof(end_time_str));
    
    printf("  Start Time:      %s\n", start_time_str);
    printf("  End Time:        %s\n", end_time_str);
    printf("  Duration:        %.6f seconds\n", stats->duration_seconds);
    if (stats->duration_seconds > 0) {
        printf("  Packet Rate:     %.2f packets/second\n", 
               stats->total_packets / stats->duration_seconds);
        printf("  Data Rate:       %.2f bytes/second (%.2f KB/s)\n", 
               stats->total_bytes / stats->duration_seconds,
               (stats->total_bytes / stats->duration_seconds) / 1024.0);
    }
    
    printf("\n[PACKET STATISTICS]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total Packets:   %u\n", stats->total_packets);
    printf("  Total Bytes:     %lu bytes (%.2f KB, %.2f MB)\n", 
           stats->total_bytes,
           stats->total_bytes / 1024.0,
           stats->total_bytes / (1024.0 * 1024.0));
    printf("  Min Packet Size: %u bytes\n", stats->min_packet_size);
    printf("  Max Packet Size: %u bytes\n", stats->max_packet_size);
    printf("  Avg Packet Size: %.2f bytes\n", stats->avg_packet_size);
    
    printf("\n[FLOW STATISTICS]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total Flows:     %u\n", stats->total_flows);
    if (stats->total_flows > 0) {
        printf("  Avg Packets/Flow:%.2f\n", 
               (double)stats->total_packets / stats->total_flows);
        printf("  Avg Bytes/Flow:  %.2f\n", 
               (double)stats->total_bytes / stats->total_flows);
    }
    
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("\n\n");
}
