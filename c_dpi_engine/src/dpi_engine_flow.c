/*
 * DPI Engine - Flow Management and Statistics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <ndpi/ndpi_api.h>
#include "dpi_engine.h"
#include "mqtt_parser.h"

/* ========== Flow Management ========== */

flow_stats_t* get_or_create_flow(dpi_engine_t *engine, 
                                  const layer3_info_t *l3,
                                  const layer4_info_t *l4) {
    
    // Search for existing flow (linear search for now - can optimize with hash table)
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        flow_stats_t *f = &engine->flows[i];
        
        // Check if flow matches (bidirectional)
        if (f->protocol == l3->protocol &&
            ((f->src_ip == l3->src_ip && f->dst_ip == l3->dst_ip &&
              f->src_port == l4->src_port && f->dst_port == l4->dst_port) ||
             (f->src_ip == l3->dst_ip && f->dst_ip == l3->src_ip &&
              f->src_port == l4->dst_port && f->dst_port == l4->src_port))) {
            return f;
        }
    }
    
    // Flow not found - create new one
    if (engine->flow_count >= engine->max_flows) {
        static int warning_count = 0;
        if (warning_count++ < 5) {
            fprintf(stderr, "[Warning] Maximum flows reached (%u) - possible DDoS attack!\n", engine->max_flows);
        }
        return NULL;
    }
    
    // Early DDoS warning when flow count is abnormally high
    if (engine->flow_count > 0 && engine->flow_count % 10000 == 0) {
        fprintf(stderr, "[Alert] High flow count detected: %u flows - analyzing for DDoS patterns...\n", 
                engine->flow_count);
    }
    
    flow_stats_t *new_flow = &engine->flows[engine->flow_count];
    memset(new_flow, 0, sizeof(flow_stats_t));
    
    // Initialize flow
    new_flow->src_ip = l3->src_ip;
    new_flow->dst_ip = l3->dst_ip;
    new_flow->src_port = l4->src_port;
    new_flow->dst_port = l4->dst_port;
    new_flow->protocol = l3->protocol;
    
    // Note: first_seen and last_seen will be set by the first packet
    // We'll initialize them to zero and set them when update_flow_stats is called
    memset(&new_flow->first_seen, 0, sizeof(struct timeval));
    memset(&new_flow->last_seen, 0, sizeof(struct timeval));
    
    new_flow->min_packet_size = 0xFFFFFFFF;
    new_flow->max_packet_size = 0;
    
    // Initialize packet storage (allocate for 1000 packets initially)
    new_flow->packet_capacity = 1000;
    new_flow->packets = (parsed_packet_t **)calloc(new_flow->packet_capacity, sizeof(parsed_packet_t *));
    new_flow->packet_count_stored = 0;
    
    // Initialize nDPI structure for this flow
    new_flow->ndpi_flow = (struct ndpi_flow_struct *)calloc(1, SIZEOF_FLOW_STRUCT);
    
    if (!new_flow->ndpi_flow) {
        fprintf(stderr, "[Error] Failed to allocate nDPI flow structure\n");
        return NULL;
    }
    
    // Already zeroed by calloc
    strcpy(new_flow->protocol_name, "Unknown");
    
    // Initialize protocol voting
    new_flow->num_candidates = 0;
    new_flow->protocol_confirmed = 0;
    memset(new_flow->protocol_counts, 0, sizeof(new_flow->protocol_counts));
    
    engine->flow_count++;
    engine->flows_created++;
    
    return new_flow;
}

/* ========== Flow Statistics Update ========== */

void update_flow_stats(flow_stats_t *flow, const parsed_packet_t *parsed) {
    // Update timestamps
    // Set first_seen on the very first packet
    if (flow->first_seen.tv_sec == 0 && flow->first_seen.tv_usec == 0) {
        flow->first_seen = parsed->timestamp;
    }
    flow->last_seen = parsed->timestamp;
    
    // Update packet counts
    flow->total_packets++;
    
    // Determine direction
    int is_forward = (flow->src_ip == parsed->layer3.src_ip);
    if (is_forward) {
        flow->packets_src_to_dst++;
        flow->bytes_src_to_dst += parsed->packet_size;
    } else {
        flow->packets_dst_to_src++;
        flow->bytes_dst_to_src += parsed->packet_size;
    }
    
    // Update byte counts
    flow->total_bytes += parsed->packet_size;
    
    // Update packet size statistics
    if (parsed->packet_size < flow->min_packet_size) {
        flow->min_packet_size = parsed->packet_size;
    }
    if (parsed->packet_size > flow->max_packet_size) {
        flow->max_packet_size = parsed->packet_size;
    }
    flow->total_packet_size += parsed->packet_size;
    
    // Calculate inter-arrival time
    if (flow->last_packet_time_us > 0) {
        uint64_t current_time_us = parsed->timestamp.tv_sec * 1000000 + 
                                   parsed->timestamp.tv_usec;
        uint64_t iat = current_time_us - flow->last_packet_time_us;
        flow->total_inter_arrival_time += iat;
        flow->inter_arrival_count++;
    }
    flow->last_packet_time_us = parsed->timestamp.tv_sec * 1000000 + 
                                parsed->timestamp.tv_usec;
    
    // Update TCP statistics
    if (parsed->layer3.protocol == IPPROTO_TCP) {
        if (parsed->layer4.tcp_flags & 0x02) {  // SYN
            flow->syn_count++;
            if (!(parsed->layer4.tcp_flags & 0x10)) {  // SYN without ACK
                flow->connection_attempts++;
            }
        }
        if (parsed->layer4.tcp_flags & 0x10) flow->ack_count++;  // ACK
        if (parsed->layer4.tcp_flags & 0x01) flow->fin_count++;  // FIN
        if (parsed->layer4.tcp_flags & 0x04) flow->rst_count++;  // RST
    }
    
    // Track unique destination ports (for port scanning detection)
    int port_exists = 0;
    for (uint16_t i = 0; i < flow->unique_dst_port_count; i++) {
        if (flow->unique_dst_ports[i] == parsed->layer4.dst_port) {
            port_exists = 1;
            break;
        }
    }
    if (!port_exists && flow->unique_dst_port_count < 1024) {
        flow->unique_dst_ports[flow->unique_dst_port_count++] = parsed->layer4.dst_port;
    }
}

/* ========== nDPI Protocol Detection ========== */

void detect_protocol(dpi_engine_t *engine, parsed_packet_t *parsed) {
    if (!parsed->flow || !parsed->flow->ndpi_flow) {
        strcpy(parsed->detected_protocol, "Unknown");
        return;
    }
    
    flow_stats_t *flow = parsed->flow;
    
    // Skip header based on datalink type
    // For LINUX_SLL: 16 bytes, LINUX_SLL2: 20 bytes, Ethernet: 14 bytes
    uint32_t offset = 14;  // Default for Ethernet
    if (parsed->raw_data_len > 20) {
        // Try to detect Linux cooked capture by checking protocol field
        uint16_t arphrd_type = (parsed->raw_data[0] << 8) | parsed->raw_data[1];
        if (arphrd_type == 1) {  // ARPHRD_ETHER - likely LINUX_SLL
            offset = 16;  // LINUX_SLL header size
        }
        // Check for LINUX_SLL2 signature (protocol field at offset 10-11)
        if (parsed->raw_data_len > 20 && parsed->raw_data[0] == 0x00 && parsed->raw_data[1] < 0x10) {
            offset = 20;  // LINUX_SLL2 header size
        }
    }
    if (parsed->layer2.has_vlan) offset += 4;
    
    // Ensure we don't go out of bounds
    if (offset >= parsed->raw_data_len) {
        strcpy(parsed->detected_protocol, "Unknown");
        return;
    }
    
    // Process packet with nDPI (nDPI 4.2.0 API)
    flow->detected_protocol = ndpi_detection_process_packet(
        engine->ndpi,
        flow->ndpi_flow,
        parsed->raw_data + offset,
        parsed->raw_data_len - offset,
        (uint64_t)parsed->timestamp.tv_sec * 1000 + parsed->timestamp.tv_usec / 1000
    );
    
    // Protocol detection enhancement - force detection after sufficient packets
    if (flow->total_packets >= 10) {
        if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
            flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
            u_int8_t protocol_was_guessed = 0;
            ndpi_protocol giveup_proto = ndpi_detection_giveup(
                engine->ndpi,
                flow->ndpi_flow,
                1,  // enable_guess
                &protocol_was_guessed
            );
            flow->detected_protocol = giveup_proto;
        }
    }
    
    // Get protocol name string - prioritize custom parsers over nDPI
    char current_protocol[64];
    
    // Check if custom parser (MQTT port, etc.) already detected a protocol
    if (strlen(parsed->detected_protocol) > 0 && 
        strcmp(parsed->detected_protocol, "Unknown") != 0) {
        // Use custom parser result (e.g., "MQTT-Port")
        strncpy(current_protocol, parsed->detected_protocol, sizeof(current_protocol) - 1);
        current_protocol[sizeof(current_protocol) - 1] = '\0';
    } else {
        // Fall back to nDPI detection
        ndpi_protocol2name(engine->ndpi, flow->detected_protocol, 
                           current_protocol, sizeof(current_protocol));
        
        // If still unknown at packet level, mark it
        if (strlen(current_protocol) == 0 ||
            (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
             flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN)) {
            snprintf(current_protocol, sizeof(current_protocol), "Unknown");
        }
    }
    
    // Protocol voting: Track protocol detections and confirm if 5+ packets match
    if (strcmp(current_protocol, "Unknown") != 0) {
        // Find if this protocol already exists in candidates
        int found_idx = -1;
        for (uint32_t i = 0; i < flow->num_candidates; i++) {
            if (strcmp(flow->candidate_protocols[i], current_protocol) == 0) {
                found_idx = i;
                break;
            }
        }
        
        if (found_idx >= 0) {
            // Increment count for existing candidate
            flow->protocol_counts[found_idx]++;
            
            // If this protocol appears 5+ times, confirm it as the flow protocol
            if (!flow->protocol_confirmed && flow->protocol_counts[found_idx] >= 5) {
                size_t len = sizeof(flow->protocol_name);
                strncpy(flow->protocol_name, current_protocol, len - 1);
                flow->protocol_name[len - 1] = '\0';
                flow->protocol_confirmed = 1;
            }
        } else if (flow->num_candidates < 10) {
            // Add new candidate protocol
            size_t len = sizeof(flow->candidate_protocols[0]);
            size_t src_len = strlen(current_protocol);
            size_t copy_len = (src_len < len - 1) ? src_len : len - 1;
            memcpy(flow->candidate_protocols[flow->num_candidates], current_protocol, copy_len);
            flow->candidate_protocols[flow->num_candidates][copy_len] = '\0';
            flow->protocol_counts[flow->num_candidates] = 1;
            flow->num_candidates++;
            
            // If this is the first non-Unknown protocol detected, use it tentatively
            if (flow->num_candidates == 1 && strcmp(flow->protocol_name, "Unknown") == 0) {
                size_t plen = sizeof(flow->protocol_name);
                strncpy(flow->protocol_name, current_protocol, plen - 1);
                flow->protocol_name[plen - 1] = '\0';
            }
        }
    }
    
    // If protocol is confirmed, use it; otherwise use current detection or "Unknown"
    if (flow->protocol_confirmed) {
        // Flow protocol is confirmed, use it
        strncpy(parsed->detected_protocol, flow->protocol_name, 
                sizeof(parsed->detected_protocol) - 1);
    } else {
        // Not yet confirmed, use current packet's detection
        strncpy(parsed->detected_protocol, current_protocol, 
                sizeof(parsed->detected_protocol) - 1);
    }
    parsed->detected_protocol[sizeof(parsed->detected_protocol) - 1] = '\0';
}

/* ========== Utility Functions ========== */

void print_mac_address(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_address(uint32_t ip) {
    printf("%u.%u.%u.%u", 
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF,
           ip & 0xFF);
}

void print_packet_info(const parsed_packet_t *parsed) {
    printf("\n========================================\n");
    printf("PACKET ANALYSIS\n");
    printf("========================================\n");
    
    // Layer 2
    printf("[Layer 2 - Data Link]\n");
    printf("  Src MAC: "); print_mac_address(parsed->layer2.src_mac); printf("\n");
    printf("  Dst MAC: "); print_mac_address(parsed->layer2.dst_mac); printf("\n");
    printf("  EtherType: 0x%04x\n", parsed->layer2.ethertype);
    if (parsed->layer2.has_vlan) {
        printf("  VLAN ID: %u\n", parsed->layer2.vlan_id);
    }
    
    // Layer 3
    printf("\n[Layer 3 - Network]\n");
    printf("  Src IP: "); print_ip_address(parsed->layer3.src_ip); printf("\n");
    printf("  Dst IP: "); print_ip_address(parsed->layer3.dst_ip); printf("\n");
    printf("  Protocol: %u ", parsed->layer3.protocol);
    if (parsed->layer3.protocol == IPPROTO_TCP) printf("(TCP)\n");
    else if (parsed->layer3.protocol == IPPROTO_UDP) printf("(UDP)\n");
    else if (parsed->layer3.protocol == IPPROTO_ICMP) printf("(ICMP)\n");
    else printf("\n");
    printf("  TTL: %u\n", parsed->layer3.ttl);
    printf("  Packet Size: %u bytes\n", parsed->layer3.packet_size);
    
    // Layer 4
    printf("\n[Layer 4 - Transport]\n");
    if (parsed->layer3.protocol == IPPROTO_TCP) {
        printf("  Protocol: TCP\n");
        printf("  Src Port: %u\n", parsed->layer4.src_port);
        printf("  Dst Port: %u\n", parsed->layer4.dst_port);
        printf("  Flags: ");
        if (parsed->layer4.tcp_flags & 0x01) printf("FIN ");
        if (parsed->layer4.tcp_flags & 0x02) printf("SYN ");
        if (parsed->layer4.tcp_flags & 0x04) printf("RST ");
        if (parsed->layer4.tcp_flags & 0x08) printf("PSH ");
        if (parsed->layer4.tcp_flags & 0x10) printf("ACK ");
        if (parsed->layer4.tcp_flags & 0x20) printf("URG ");
        printf("\n");
    } else if (parsed->layer3.protocol == IPPROTO_UDP) {
        printf("  Protocol: UDP\n");
        printf("  Src Port: %u\n", parsed->layer4.src_port);
        printf("  Dst Port: %u\n", parsed->layer4.dst_port);
        printf("  Length: %u\n", parsed->layer4.udp_length);
    } else if (parsed->layer3.protocol == IPPROTO_ICMP) {
        printf("  Protocol: ICMP\n");
        printf("  Type: %u, Code: %u\n", 
               parsed->layer4.icmp_type, parsed->layer4.icmp_code);
    }
    
    // Layer 5
    printf("\n[Layer 5 - Session]\n");
    printf("  Flow State: %s\n", parsed->layer5.flow_state);
    printf("  5-Tuple: ");
    print_ip_address(parsed->layer5.src_ip);
    printf(":%u -> ", parsed->layer5.src_port);
    print_ip_address(parsed->layer5.dst_ip);
    printf(":%u (proto:%u)\n", parsed->layer5.dst_port, parsed->layer5.protocol);
    
    // Layer 7
    printf("\n[Layer 7 - Application (Partial)]\n");
    printf("  Detected Protocol: %s\n", parsed->detected_protocol);
    
    printf("========================================\n");
}

/* ========== Timestamp Formatting ========== */

void format_timestamp(const struct timeval *ts, char *buffer, size_t buf_size) {
    time_t sec = ts->tv_sec;
    struct tm *tm_info = localtime(&sec);
    char time_str[64];
    
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(buffer, buf_size, "%s.%06ld", time_str, (long)ts->tv_usec);
}

const char* get_protocol_name(uint8_t protocol) {
    switch(protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        case IPPROTO_SCTP: return "SCTP";
        default: return "Unknown";
    }
}

/* ========== Store Packet in Flow ========== */

void store_packet_in_flow(flow_stats_t *flow, const parsed_packet_t *parsed) {
    if (!flow || !parsed) return;
    
    // Expand array if needed
    if (flow->packet_count_stored >= flow->packet_capacity) {
        flow->packet_capacity *= 2;
        flow->packets = (parsed_packet_t **)realloc(flow->packets, 
                                                     flow->packet_capacity * sizeof(parsed_packet_t *));
    }
    
    // Allocate and copy packet structure
    parsed_packet_t *pkt_copy = (parsed_packet_t *)malloc(sizeof(parsed_packet_t));
    memcpy(pkt_copy, parsed, sizeof(parsed_packet_t));
    
    // IMPORTANT: Copy raw packet data (not just the pointer!)
    if (parsed->raw_data && parsed->raw_data_len > 0) {
        pkt_copy->raw_data = (uint8_t *)malloc(parsed->raw_data_len);
        if (pkt_copy->raw_data) {
            memcpy((void*)pkt_copy->raw_data, parsed->raw_data, parsed->raw_data_len);
        }
    } else {
        pkt_copy->raw_data = NULL;
    }
    
    // Store in flow
    flow->packets[flow->packet_count_stored++] = pkt_copy;
}

/* ========== Print Flow with All Its Packets ========== */

void print_flow_with_packets(const flow_stats_t *flow, uint32_t flow_num) {
    printf("\n");
    printf("████████████████████████████████████████████████████████████████\n");
    printf("█                    FLOW #%u ANALYSIS                        █\n", flow_num);
    printf("████████████████████████████████████████████████████████████████\n");
    
    // Print flow summary
    printf("\n[FLOW SUMMARY]\n");
    printf("========================================\n");
    printf("5-Tuple: ");
    print_ip_address(flow->src_ip);
    printf(":%u <-> ", flow->src_port);
    print_ip_address(flow->dst_ip);
    printf(":%u\n", flow->dst_port);
    printf("Transport Protocol: %u (%s)\n", flow->protocol, get_protocol_name(flow->protocol));
    
    // Time information
    char first_seen_str[128], last_seen_str[128];
    format_timestamp(&flow->first_seen, first_seen_str, sizeof(first_seen_str));
    format_timestamp(&flow->last_seen, last_seen_str, sizeof(last_seen_str));
    
    printf("\n[TIME INFORMATION]\n");
    printf("  First Seen: %s\n", first_seen_str);
    printf("  Last Seen:  %s\n", last_seen_str);
    
    double duration = (flow->last_seen.tv_sec - flow->first_seen.tv_sec) + 
                      (flow->last_seen.tv_usec - flow->first_seen.tv_usec) / 1000000.0;
    printf("  Duration:   %.6f seconds\n", duration);
    
    // Packet and byte statistics
    printf("\n[TRAFFIC STATISTICS]\n");
    printf("  Total Packets: %lu\n", flow->total_packets);
    printf("  Packets (Src->Dst): %lu\n", flow->packets_src_to_dst);
    printf("  Packets (Dst->Src): %lu\n", flow->packets_dst_to_src);
    printf("  Total Bytes: %lu\n", flow->total_bytes);
    printf("  Bytes (Src->Dst): %lu\n", flow->bytes_src_to_dst);
    printf("  Bytes (Dst->Src): %lu\n", flow->bytes_dst_to_src);
    
    // Packet size statistics
    printf("\n[PACKET SIZE STATISTICS]\n");
    printf("  Min Packet Size: %u bytes\n", flow->min_packet_size);
    printf("  Max Packet Size: %u bytes\n", flow->max_packet_size);
    if (flow->total_packets > 0) {
        printf("  Avg Packet Size: %lu bytes\n", 
               flow->total_packet_size / flow->total_packets);
    }
    
    // TCP-specific statistics
    if (flow->protocol == IPPROTO_TCP) {
        printf("\n[TCP STATISTICS]\n");
        printf("  SYN Count: %u\n", flow->syn_count);
        printf("  ACK Count: %u\n", flow->ack_count);
        printf("  FIN Count: %u\n", flow->fin_count);
        printf("  RST Count: %u\n", flow->rst_count);
        printf("  Connection Attempts: %u\n", flow->connection_attempts);
        printf("  Connection State: ");
        if (flow->syn_count > 0 && flow->ack_count > 0) printf("ESTABLISHED\n");
        else if (flow->syn_count > 0) printf("SYN_SENT\n");
        else printf("ACTIVE\n");
    }
    
    // Inter-arrival time
    if (flow->inter_arrival_count > 0) {
        printf("\n[TIMING ANALYSIS]\n");
        printf("  Avg Inter-arrival Time: %lu μs\n",
               flow->total_inter_arrival_time / flow->inter_arrival_count);
    }
    
    // Protocol detection
    printf("\n[LAYER 7 PROTOCOL DETECTION]\n");
    printf("  Detected Protocol: %s\n", flow->protocol_name);
    
    // Port scanning detection
    if (flow->unique_dst_port_count > 1) {
        printf("\n[SECURITY ANALYSIS]\n");
        printf("  Unique Destination Ports Accessed: %u\n", flow->unique_dst_port_count);
        if (flow->unique_dst_port_count > 10) {
            printf("  ⚠️  WARNING: Possible port scanning activity detected!\n");
        }
        if (flow->unique_dst_port_count <= 20) {
            printf("  Ports: ");
            for (uint16_t i = 0; i < flow->unique_dst_port_count; i++) {
                printf("%u ", flow->unique_dst_ports[i]);
            }
            printf("\n");
        }
    }
    
    // Now print all packets in this flow
    printf("\n");
    printf("════════════════════════════════════════════════════════════════\n");
    printf("         DETAILED PACKET ANALYSIS FOR FLOW #%u\n", flow_num);
    printf("         Total Packets in Flow: %u\n", flow->packet_count_stored);
    printf("════════════════════════════════════════════════════════════════\n\n");
    
    for (uint32_t i = 0; i < flow->packet_count_stored; i++) {
        parsed_packet_t *pkt = flow->packets[i];
        
        printf("\n┌─────────────────────────────────────────────────────────────┐\n");
        printf("│  PACKET #%u (Flow Packet #%u)                                \n", 
               pkt->packet_number, i + 1);
        printf("└─────────────────────────────────────────────────────────────┘\n");
        
        char pkt_time_str[128];
        format_timestamp(&pkt->timestamp, pkt_time_str, sizeof(pkt_time_str));
        
        printf("\n[PACKET METADATA]\n");
        printf("  Timestamp:   %s\n", pkt_time_str);
        printf("  Packet Size: %u bytes\n", pkt->packet_size);
        
        printf("\n[LAYER 2 - DATA LINK]\n");
        printf("  Source MAC:      ");
        print_mac_address(pkt->layer2.src_mac);
        printf("\n  Destination MAC: ");
        print_mac_address(pkt->layer2.dst_mac);
        printf("\n  EtherType:       0x%04x\n", pkt->layer2.ethertype);
        if (pkt->layer2.has_vlan) {
            printf("  VLAN ID:         %u\n", pkt->layer2.vlan_id);
        }
        
        printf("\n[LAYER 3 - NETWORK]\n");
        printf("  Source IP:       ");
        print_ip_address(pkt->layer3.src_ip);
        printf("\n  Destination IP:  ");
        print_ip_address(pkt->layer3.dst_ip);
        printf("\n  Protocol:        %u ", pkt->layer3.protocol);
        if (pkt->layer3.protocol == IPPROTO_TCP) printf("(TCP)");
        else if (pkt->layer3.protocol == IPPROTO_UDP) printf("(UDP)");
        else if (pkt->layer3.protocol == IPPROTO_ICMP) printf("(ICMP)");
        printf("\n  TTL:             %u\n", pkt->layer3.ttl);
        printf("  IP Packet Size:  %u bytes\n", pkt->layer3.packet_size);
        printf("  Identification:  %u\n", pkt->layer3.identification);
        
        printf("\n[LAYER 4 - TRANSPORT]\n");
        if (pkt->layer3.protocol == IPPROTO_TCP) {
            printf("  Source Port:     %u\n", pkt->layer4.src_port);
            printf("  Destination Port:%u\n", pkt->layer4.dst_port);
            printf("  Sequence Number: %u\n", pkt->layer4.seq_number);
            printf("  ACK Number:      %u\n", pkt->layer4.ack_number);
            printf("  Window Size:     %u\n", pkt->layer4.window_size);
            printf("  TCP Flags:       ");
            if (pkt->layer4.tcp_flags & 0x01) printf("FIN ");
            if (pkt->layer4.tcp_flags & 0x02) printf("SYN ");
            if (pkt->layer4.tcp_flags & 0x04) printf("RST ");
            if (pkt->layer4.tcp_flags & 0x08) printf("PSH ");
            if (pkt->layer4.tcp_flags & 0x10) printf("ACK ");
            if (pkt->layer4.tcp_flags & 0x20) printf("URG ");
            printf("\n");
        } else if (pkt->layer3.protocol == IPPROTO_UDP) {
            printf("  Source Port:     %u\n", pkt->layer4.src_port);
            printf("  Destination Port:%u\n", pkt->layer4.dst_port);
            printf("  UDP Length:      %u\n", pkt->layer4.udp_length);
        } else if (pkt->layer3.protocol == IPPROTO_ICMP) {
            printf("  ICMP Type:       %u\n", pkt->layer4.icmp_type);
            printf("  ICMP Code:       %u\n", pkt->layer4.icmp_code);
        }
        
        printf("\n[LAYER 5 - SESSION]\n");
        printf("  Flow State:      %s\n", pkt->layer5.flow_state);
        printf("  Direction:       ");
        if (pkt->layer3.src_ip == flow->src_ip) {
            printf("Forward (Src->Dst)\n");
        } else {
            printf("Reverse (Dst->Src)\n");
        }
        
        printf("\n[LAYER 7 - APPLICATION]\n");
        printf("  Protocol:        %s\n", pkt->detected_protocol);
        
        // Print MQTT-specific information if available
        if (pkt->is_mqtt) {
            printf("\n[MQTT PROTOCOL DETAILS]\n");
            printf("  MQTT Packet Type: %s\n", mqtt_get_packet_type_name(pkt->mqtt_packet_type));
            
            if (pkt->mqtt_packet_type == MQTT_CONNECT && strlen(pkt->mqtt_client_id) > 0) {
                printf("  Client ID:        %s\n", pkt->mqtt_client_id);
            }
            
            if (pkt->mqtt_packet_type == MQTT_PUBLISH) {
                if (strlen(pkt->mqtt_topic) > 0) {
                    printf("  Topic:            %s\n", pkt->mqtt_topic);
                }
                printf("  Payload Length:   %u bytes\n", pkt->mqtt_payload_length);
                
                // Display actual payload content (sensor values)
                if (strlen(pkt->mqtt_payload_data) > 0) {
                    printf("  Payload Data:     %s\n", pkt->mqtt_payload_data);
                }
            }
        }
        
        printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }
    
    printf("\n\n");
}

void print_flow_stats(const flow_stats_t *flow) {
    printf("\n========================================\n");
    printf("FLOW STATISTICS\n");
    printf("========================================\n");
    printf("5-Tuple: ");
    print_ip_address(flow->src_ip);
    printf(":%u -> ", flow->src_port);
    print_ip_address(flow->dst_ip);
    printf(":%u (proto:%u)\n", flow->dst_port, flow->protocol);
    
    printf("\nPackets: %lu (fwd:%lu, rev:%lu)\n", 
           flow->total_packets, flow->packets_src_to_dst, flow->packets_dst_to_src);
    printf("Bytes: %lu (fwd:%lu, rev:%lu)\n", 
           flow->total_bytes, flow->bytes_src_to_dst, flow->bytes_dst_to_src);
    
    if (flow->protocol == IPPROTO_TCP) {
        printf("\nTCP Stats:\n");
        printf("  SYN: %u, ACK: %u, FIN: %u, RST: %u\n",
               flow->syn_count, flow->ack_count, flow->fin_count, flow->rst_count);
        printf("  Connection attempts: %u\n", flow->connection_attempts);
    }
    
    printf("\nPacket Sizes:\n");
    printf("  Min: %u, Max: %u, Avg: %lu\n",
           flow->min_packet_size, flow->max_packet_size,
           flow->total_packets > 0 ? flow->total_packet_size / flow->total_packets : 0);
    
    printf("\nPort Scanning Detection:\n");
    printf("  Unique destination ports accessed: %u\n", flow->unique_dst_port_count);
    if (flow->unique_dst_port_count > 0 && flow->unique_dst_port_count <= 10) {
        printf("  Ports: ");
        for (uint16_t i = 0; i < flow->unique_dst_port_count; i++) {
            printf("%u ", flow->unique_dst_ports[i]);
        }
        printf("\n");
    }
    
    if (flow->inter_arrival_count > 0) {
        printf("\nInter-arrival time: %lu μs (avg)\n",
               flow->total_inter_arrival_time / flow->inter_arrival_count);
    }
    
    printf("\nDetected Protocol: %s\n", flow->protocol_name);
    printf("========================================\n");
}