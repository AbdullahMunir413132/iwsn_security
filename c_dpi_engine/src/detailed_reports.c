/*
 * DPI Detailed Report Generator
 * Generates comprehensive PCAP analysis with file stats, flow-by-flow, and packet-by-packet details
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "dpi_engine.h"

void generate_dpi_detailed_report(dpi_engine_t *engine, pcap_stats_t *pcap_stats, const char *output_file) {
    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", output_file);
        return;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // ========== PCAP FILE DETAILED ANALYSIS SUMMARY ==========
    fprintf(fp, "\n╔════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                                                                ║\n");
    fprintf(fp, "║              PCAP FILE DETAILED ANALYSIS SUMMARY               ║\n");
    fprintf(fp, "║                                                                ║\n");
    fprintf(fp, "╚════════════════════════════════════════════════════════════════╝\n\n");
    
    // File Information
    fprintf(fp, "[FILE INFORMATION]\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Filename:        %s\n", pcap_stats->filename);
    fprintf(fp, "  File Size:       %lu bytes (%.2f KB, %.2f MB)\n\n",
           pcap_stats->file_size,
           pcap_stats->file_size / 1024.0,
           pcap_stats->file_size / (1024.0 * 1024.0));
    
    // Capture Timing
    fprintf(fp, "[CAPTURE TIMING]\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n");
    char start_time[64], end_time[64];
    strftime(start_time, sizeof(start_time), "%Y-%m-%d %H:%M:%S", localtime(&pcap_stats->start_time.tv_sec));
    strftime(end_time, sizeof(end_time), "%Y-%m-%d %H:%M:%S", localtime(&pcap_stats->end_time.tv_sec));
    fprintf(fp, "  Start Time:      %s.%06ld\n", start_time, pcap_stats->start_time.tv_usec);
    fprintf(fp, "  End Time:        %s.%06ld\n", end_time, pcap_stats->end_time.tv_usec);
    fprintf(fp, "  Duration:        %.6f seconds\n", pcap_stats->duration_seconds);
    if (pcap_stats->duration_seconds > 0) {
        fprintf(fp, "  Packet Rate:     %.2f packets/second\n",
               pcap_stats->total_packets / pcap_stats->duration_seconds);
        fprintf(fp, "  Data Rate:       %.2f bytes/second (%.2f KB/s)\n\n",
               pcap_stats->total_bytes / pcap_stats->duration_seconds,
               (pcap_stats->total_bytes / pcap_stats->duration_seconds) / 1024.0);
    } else {
        fprintf(fp, "  Packet Rate:     N/A (instantaneous capture)\n");
        fprintf(fp, "  Data Rate:       N/A (instantaneous capture)\n\n");
    }
    
    // Packet Statistics
    fprintf(fp, "[PACKET STATISTICS]\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Total Packets:   %u\n", pcap_stats->total_packets);
    fprintf(fp, "  Total Bytes:     %lu bytes (%.2f KB, %.2f MB)\n",
           pcap_stats->total_bytes,
           pcap_stats->total_bytes / 1024.0,
           pcap_stats->total_bytes / (1024.0 * 1024.0));
    fprintf(fp, "  Min Packet Size: %u bytes\n", pcap_stats->min_packet_size);
    fprintf(fp, "  Max Packet Size: %u bytes\n", pcap_stats->max_packet_size);
    fprintf(fp, "  Avg Packet Size: %.2f bytes\n\n", pcap_stats->avg_packet_size);
    
    // Flow Statistics
    fprintf(fp, "[FLOW STATISTICS]\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  Total Flows:     %u\n", pcap_stats->total_flows);
    if (pcap_stats->total_flows > 0) {
        fprintf(fp, "  Avg Packets/Flow:%.2f\n", (double)pcap_stats->total_packets / pcap_stats->total_flows);
        fprintf(fp, "  Avg Bytes/Flow:  %.2f\n\n", (double)pcap_stats->total_bytes / pcap_stats->total_flows);
    } else {
        fprintf(fp, "  Avg Packets/Flow:N/A\n");
        fprintf(fp, "  Avg Bytes/Flow:  N/A\n\n");
    }
    
    fprintf(fp, "═══════════════════════════════════════════════════════════════\n\n\n");
    
    // ========== DETAILED FLOW-BY-FLOW ANALYSIS ==========
    fprintf(fp, "\n╔════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                                                                ║\n");
    fprintf(fp, "║            DETAILED FLOW-BY-FLOW ANALYSIS BEGINS               ║\n");
    fprintf(fp, "║                  Total Flows: %-3u                              ║\n", engine->flow_count);
    fprintf(fp, "║                                                                ║\n");
    fprintf(fp, "╚════════════════════════════════════════════════════════════════╝\n\n");
    
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        flow_stats_t *flow = &engine->flows[i];
        
        fprintf(fp, "████████████████████████████████████████████████████████████████\n");
        fprintf(fp, "█                    FLOW #%-3u ANALYSIS                        █\n", i+1);
        fprintf(fp, "████████████████████████████████████████████████████████████████\n\n");
        
        // Flow Summary
        fprintf(fp, "[FLOW SUMMARY]\n");
        fprintf(fp, "========================================\n");
        fprintf(fp, "5-Tuple: %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u\n",
               (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
               (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF, flow->src_port,
               (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
               (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF, flow->dst_port);
        fprintf(fp, "Transport Protocol: %u ", flow->protocol);
        if (flow->protocol == 6) fprintf(fp, "(TCP)");
        else if (flow->protocol == 17) fprintf(fp, "(UDP)");
        else if (flow->protocol == 1) fprintf(fp, "(ICMP)");
        fprintf(fp, "\n\n");
        
        // Time Information
        fprintf(fp, "[TIME INFORMATION]\n");
        char first_time[64], last_time[64];
        strftime(first_time, sizeof(first_time), "%Y-%m-%d %H:%M:%S", localtime(&flow->first_seen.tv_sec));
        strftime(last_time, sizeof(last_time), "%Y-%m-%d %H:%M:%S", localtime(&flow->last_seen.tv_sec));
        fprintf(fp, "  First Seen: %s.%06ld\n", first_time, flow->first_seen.tv_usec);
        fprintf(fp, "  Last Seen:  %s.%06ld\n", last_time, flow->last_seen.tv_usec);
        double duration = flow->last_seen.tv_sec - flow->first_seen.tv_sec +
                         (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
        fprintf(fp, "  Duration:   %.6f seconds\n\n", duration);
        
        // Traffic Statistics
        fprintf(fp, "[TRAFFIC STATISTICS]\n");
        fprintf(fp, "  Total Packets: %lu\n", flow->total_packets);
        fprintf(fp, "  Packets (Src->Dst): %lu\n", flow->packets_src_to_dst);
        fprintf(fp, "  Packets (Dst->Src): %lu\n", flow->packets_dst_to_src);
        fprintf(fp, "  Total Bytes: %lu\n", flow->total_bytes);
        fprintf(fp, "  Bytes (Src->Dst): %lu\n", flow->bytes_src_to_dst);
        fprintf(fp, "  Bytes (Dst->Src): %lu\n\n", flow->bytes_dst_to_src);
        
        // Packet Size Statistics
        fprintf(fp, "[PACKET SIZE STATISTICS]\n");
        fprintf(fp, "  Min Packet Size: %u bytes\n", flow->min_packet_size);
        fprintf(fp, "  Max Packet Size: %u bytes\n", flow->max_packet_size);
        if (flow->total_packets > 0) {
            fprintf(fp, "  Avg Packet Size: %lu bytes\n\n", flow->total_bytes / flow->total_packets);
        } else {
            fprintf(fp, "  Avg Packet Size: 0 bytes\n\n");
        }
        
        // TCP Statistics
        if (flow->protocol == 6) {
            fprintf(fp, "[TCP STATISTICS]\n");
            fprintf(fp, "  SYN Count: %u\n", flow->syn_count);
            fprintf(fp, "  ACK Count: %u\n", flow->ack_count);
            fprintf(fp, "  FIN Count: %u\n", flow->fin_count);
            fprintf(fp, "  RST Count: %u\n", flow->rst_count);
            fprintf(fp, "  Connection Attempts: %u\n", flow->connection_attempts);
            fprintf(fp, "  Connection State: %s\n\n",
                   (flow->syn_count > 0 && flow->ack_count > 0 ? "ESTABLISHED" : 
                    flow->syn_count > 0 && flow->ack_count == 0 ? "SYN_SENT" :
                    flow->fin_count > 0 ? "CLOSING" : "ACTIVE"));
        }
        
        // Timing Analysis
        fprintf(fp, "[TIMING ANALYSIS]\n");
        if (flow->total_packets > 1 && duration > 0) {
            uint64_t avg_interarrival = (uint64_t)(duration * 1000000.0 / (flow->total_packets - 1));
            fprintf(fp, "  Avg Inter-arrival Time: %lu μs\n\n", avg_interarrival);
        } else {
            fprintf(fp, "  Avg Inter-arrival Time: N/A\n\n");
        }
        
        // Layer 7 Protocol Detection
        fprintf(fp, "[LAYER 7 PROTOCOL DETECTION]\n");
        fprintf(fp, "  Detected Protocol: %s\n\n", flow->protocol_name);
        
        // Security Analysis
        fprintf(fp, "[SECURITY ANALYSIS]\n");
        fprintf(fp, "  Unique Destination Ports Accessed: %u\n", flow->unique_dst_port_count);
        fprintf(fp, "  Ports:");
        for (uint32_t p = 0; p < flow->unique_dst_port_count && p < 10; p++) {
            fprintf(fp, " %u", flow->unique_dst_ports[p]);
        }
        fprintf(fp, " \n\n");
        
        // Packet-by-Packet Analysis for this flow
        fprintf(fp, "════════════════════════════════════════════════════════════════\n");
        fprintf(fp, "         DETAILED PACKET ANALYSIS FOR FLOW #%u\n", i+1);
        fprintf(fp, "         Total Packets in Flow: %lu\n", flow->total_packets);
        fprintf(fp, "════════════════════════════════════════════════════════════════\n\n\n");
        
        // Print packets (limit to 50 per flow)
        uint32_t packet_display_limit = (flow->packet_count_stored < 50) ? flow->packet_count_stored : 50;
        uint32_t global_pkt_num = 0;
        
        // Calculate global packet number (sum of packets in previous flows)
        for (uint32_t prev = 0; prev < i; prev++) {
            global_pkt_num += engine->flows[prev].packet_count_stored;
        }
        
        for (uint32_t p = 0; p < packet_display_limit; p++) {
            parsed_packet_t *pkt = flow->packets[p];
            global_pkt_num++;
            
            fprintf(fp, "┌─────────────────────────────────────────────────────────────┐\n");
            fprintf(fp, "│  PACKET #%-3u (Flow Packet #%-3u)                                \n", global_pkt_num, p+1);
            fprintf(fp, "└─────────────────────────────────────────────────────────────┘\n\n");
            
            // Packet Metadata
            fprintf(fp, "[PACKET METADATA]\n");
            char pkt_time[64];
            strftime(pkt_time, sizeof(pkt_time), "%Y-%m-%d %H:%M:%S", localtime(&pkt->timestamp.tv_sec));
            fprintf(fp, "  Timestamp:   %s.%06ld\n", pkt_time, pkt->timestamp.tv_usec);
            fprintf(fp, "  Packet Size: %u bytes\n\n", pkt->packet_size);
            
            // Layer 2
            fprintf(fp, "[LAYER 2 - DATA LINK]\n");
            fprintf(fp, "  Source MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
                   pkt->layer2.src_mac[0], pkt->layer2.src_mac[1], pkt->layer2.src_mac[2],
                   pkt->layer2.src_mac[3], pkt->layer2.src_mac[4], pkt->layer2.src_mac[5]);
            fprintf(fp, "  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   pkt->layer2.dst_mac[0], pkt->layer2.dst_mac[1], pkt->layer2.dst_mac[2],
                   pkt->layer2.dst_mac[3], pkt->layer2.dst_mac[4], pkt->layer2.dst_mac[5]);
            fprintf(fp, "  EtherType:       0x%04x\n\n", pkt->layer2.ethertype);
            
            // Layer 3
            fprintf(fp, "[LAYER 3 - NETWORK]\n");
            fprintf(fp, "  Source IP:       %u.%u.%u.%u\n",
                   (pkt->layer3.src_ip >> 24) & 0xFF, (pkt->layer3.src_ip >> 16) & 0xFF,
                   (pkt->layer3.src_ip >> 8) & 0xFF, pkt->layer3.src_ip & 0xFF);
            fprintf(fp, "  Destination IP:  %u.%u.%u.%u\n",
                   (pkt->layer3.dst_ip >> 24) & 0xFF, (pkt->layer3.dst_ip >> 16) & 0xFF,
                   (pkt->layer3.dst_ip >> 8) & 0xFF, pkt->layer3.dst_ip & 0xFF);
            fprintf(fp, "  Protocol:        %u ", pkt->layer3.protocol);
            if (pkt->layer3.protocol == 6) fprintf(fp, "(TCP)");
            else if (pkt->layer3.protocol == 17) fprintf(fp, "(UDP)");
            else if (pkt->layer3.protocol == 1) fprintf(fp, "(ICMP)");
            fprintf(fp, "\n");
            fprintf(fp, "  TTL:             %u\n", pkt->layer3.ttl);
            fprintf(fp, "  IP Packet Size:  %u bytes\n", pkt->layer3.packet_size);
            fprintf(fp, "  Identification:  %u\n\n", pkt->layer3.identification);
            
            // Layer 4
            fprintf(fp, "[LAYER 4 - TRANSPORT]\n");
            if (pkt->layer4.protocol == 6) {  // TCP
                fprintf(fp, "  Source Port:     %u\n", pkt->layer4.src_port);
                fprintf(fp, "  Destination Port:%u\n", pkt->layer4.dst_port);
                fprintf(fp, "  Sequence Number: %u\n", pkt->layer4.seq_number);
                fprintf(fp, "  ACK Number:      %u\n", pkt->layer4.ack_number);
                fprintf(fp, "  Window Size:     %u\n", pkt->layer4.window_size);
                fprintf(fp, "  TCP Flags:       ");
                if (pkt->layer4.tcp_flags & 0x02) fprintf(fp, "SYN ");
                if (pkt->layer4.tcp_flags & 0x10) fprintf(fp, "ACK ");
                if (pkt->layer4.tcp_flags & 0x01) fprintf(fp, "FIN ");
                if (pkt->layer4.tcp_flags & 0x04) fprintf(fp, "RST ");
                if (pkt->layer4.tcp_flags & 0x08) fprintf(fp, "PSH ");
                fprintf(fp, "\n\n");
            } else if (pkt->layer4.protocol == 17) {  // UDP
                fprintf(fp, "  Source Port:     %u\n", pkt->layer4.src_port);
                fprintf(fp, "  Destination Port:%u\n", pkt->layer4.dst_port);
                fprintf(fp, "  UDP Length:      %u\n\n", pkt->layer4.udp_length);
            } else if (pkt->layer4.protocol == 1) {  // ICMP
                fprintf(fp, "  ICMP Type:       %u\n", pkt->layer4.icmp_type);
                fprintf(fp, "  ICMP Code:       %u\n\n", pkt->layer4.icmp_code);
            }
            
            // Layer 5
            fprintf(fp, "[LAYER 5 - SESSION]\n");
            fprintf(fp, "  Flow State:      %s\n", pkt->layer5.flow_state);
            // Determine direction
            if (pkt->layer3.src_ip == flow->src_ip && pkt->layer4.src_port == flow->src_port) {
                fprintf(fp, "  Direction:       Forward (Src->Dst)\n\n");
            } else {
                fprintf(fp, "  Direction:       Reverse (Dst->Src)\n\n");
            }
            
            // Layer 7
            fprintf(fp, "[LAYER 7 - APPLICATION]\n");
            fprintf(fp, "  Protocol:        %s\n\n", flow->protocol_name);
            
            fprintf(fp, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        }
        
        if (flow->packet_count_stored > 50) {
            fprintf(fp, "... and %u more packets (limited to 50 per flow)\n\n", 
                   flow->packet_count_stored - 50);
        }
        
        fprintf(fp, "\n\n");
    }
    
    // ========== PROTOCOL DISTRIBUTION SUMMARY ==========
    fprintf(fp, "\n╔════════════════════════════════════════════════════════════════╗\n");
    fprintf(fp, "║                                                                ║\n");
    fprintf(fp, "║                  PROTOCOL DISTRIBUTION SUMMARY                 ║\n");
    fprintf(fp, "║                                                                ║\n");
    fprintf(fp, "╚════════════════════════════════════════════════════════════════╝\n\n");
    
    // Count protocols
    typedef struct {
        char name[64];
        uint32_t count;
    } protocol_count_t;
    
    protocol_count_t protocols[100];
    uint32_t protocol_types = 0;
    
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        flow_stats_t *flow = &engine->flows[i];
        
        // Check if protocol already exists
        int found = 0;
        for (uint32_t j = 0; j < protocol_types; j++) {
            if (strcmp(protocols[j].name, flow->protocol_name) == 0) {
                protocols[j].count++;
                found = 1;
                break;
            }
        }
        
        // Add new protocol
        if (!found && protocol_types < 100) {
            strncpy(protocols[protocol_types].name, flow->protocol_name, sizeof(protocols[protocol_types].name) - 1);
            protocols[protocol_types].count = 1;
            protocol_types++;
        }
    }
    
    // Print protocol distribution
    for (uint32_t i = 0; i < protocol_types; i++) {
        fprintf(fp, "  %-15s %u flows\n", protocols[i].name, protocols[i].count);
    }
    
    fprintf(fp, "\n═══════════════════════════════════════════════════════════════\n");
    
    fclose(fp);
    printf("✓ DPI detailed report saved to: %s\n", output_file);
}
