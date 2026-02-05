/*
 * DPI Engine - Main Implementation
 * Complete Layer 2-5 parsing + nDPI for Layer 7 protocol detection
 * Integrated with MQTT parser for deep application layer analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ndpi/ndpi_api.h>
#include "dpi_engine.h"
#include "mqtt_parser.h"

/* ========== Engine Initialization ========== */

dpi_engine_t* dpi_engine_init(uint32_t max_flows) {
    dpi_engine_t *engine = calloc(1, sizeof(dpi_engine_t));
    if (!engine) {
        fprintf(stderr, "Failed to allocate DPI engine\n");
        return NULL;
    }
    
    // Initialize nDPI (version 4.x)
    engine->ndpi = ndpi_init_detection_module(0);
    if (!engine->ndpi) {
        fprintf(stderr, "Failed to initialize nDPI\n");
        free(engine);
        return NULL;
    }
    
    // In nDPI 4.x, all protocols are enabled by default after finalize
    ndpi_finalize_initialization(engine->ndpi);
    
    // Allocate flow table
    engine->max_flows = max_flows;
    engine->flows = calloc(max_flows, sizeof(flow_stats_t));
    if (!engine->flows) {
        fprintf(stderr, "Failed to allocate flow table\n");
        ndpi_exit_detection_module(engine->ndpi);
        free(engine);
        return NULL;
    }
    
    engine->flow_count = 0;
    engine->total_packets = 0;
    engine->total_bytes = 0;
    
    // Initialize MQTT parser
    if (mqtt_parser_init() < 0) {
        fprintf(stderr, "[Warning] Failed to initialize MQTT parser\n");
    }
    
    printf("[DPI Engine] Initialized with max_flows=%u\n", max_flows);
    printf("[DPI Engine] nDPI version: %s\n", ndpi_revision());
    printf("[DPI Engine] MQTT parser enabled\n");
    
    return engine;
}

void dpi_engine_destroy(dpi_engine_t *engine) {
    if (!engine) return;
    
    // Free nDPI flow structures and packet storage
    for (uint32_t i = 0; i < engine->flow_count; i++) {
        if (engine->flows[i].ndpi_flow) {
            ndpi_free(engine->flows[i].ndpi_flow);
        }
        // Free stored packets
        if (engine->flows[i].packets) {
            for (uint32_t j = 0; j < engine->flows[i].packet_count_stored; j++) {
                free(engine->flows[i].packets[j]);
            }
            free(engine->flows[i].packets);
        }
    }
    
    if (engine->flows) {
        free(engine->flows);
    }
    
    if (engine->ndpi) {
        ndpi_exit_detection_module(engine->ndpi);
    }
    
    free(engine);
    printf("[DPI Engine] Destroyed\n");
}

/* ========== Layer 2 Parsing ========== */

int parse_layer2(const uint8_t *packet, uint32_t packet_len, layer2_info_t *l2) {
    if (packet_len < 14) {
        return -1;  // Too short for Ethernet header
    }
    
    struct ethhdr *eth = (struct ethhdr *)packet;
    
    // Extract MAC addresses
    memcpy(l2->src_mac, eth->h_source, 6);
    memcpy(l2->dst_mac, eth->h_dest, 6);
    
    // Extract EtherType
    l2->ethertype = ntohs(eth->h_proto);
    
    // Check for VLAN (802.1Q)
    l2->has_vlan = 0;
    l2->vlan_id = 0;
    
    if (l2->ethertype == 0x8100) {  // VLAN tagged
        if (packet_len < 18) {
            return -1;
        }
        l2->has_vlan = 1;
        // VLAN tag is at offset 14-15
        uint16_t vlan_tci = ntohs(*(uint16_t *)(packet + 14));
        l2->vlan_id = vlan_tci & 0x0FFF;
        // Real EtherType is after VLAN tag
        l2->ethertype = ntohs(*(uint16_t *)(packet + 16));
    }
    
    return 0;
}

/* ========== Layer 3 Parsing ========== */

int parse_layer3(const uint8_t *packet, uint32_t packet_len, layer3_info_t *l3) {
    // Skip Ethernet header (14 bytes or 18 if VLAN)
    uint32_t offset = 14;
    
    // Check for VLAN
    uint16_t ethertype = ntohs(*(uint16_t *)(packet + 12));
    if (ethertype == 0x8100) {
        offset = 18;
        ethertype = ntohs(*(uint16_t *)(packet + 16));
    }
    
    // Only process IPv4 for now
    if (ethertype != 0x0800) {
        return -1;  // Not IPv4
    }
    
    if (packet_len < offset + 20) {
        return -1;  // Too short for IP header
    }
    
    struct iphdr *ip = (struct iphdr *)(packet + offset);
    
    // Extract IP header fields
    l3->version = ip->version;
    l3->header_length = ip->ihl * 4;
    l3->protocol = ip->protocol;
    l3->ttl = ip->ttl;
    l3->packet_size = ntohs(ip->tot_len);
    l3->identification = ntohs(ip->id);
    l3->checksum = ntohs(ip->check);
    
    // Extract flags and fragment offset
    uint16_t frag_off = ntohs(ip->frag_off);
    l3->flags = (frag_off >> 13) & 0x07;
    l3->fragment_offset = frag_off & 0x1FFF;
    
    // Extract IP addresses
    l3->src_ip = ntohl(ip->saddr);
    l3->dst_ip = ntohl(ip->daddr);
    
    return 0;
}

/* ========== Layer 4 Parsing ========== */

int parse_layer4(const uint8_t *packet, uint32_t packet_len, 
                 const layer3_info_t *l3, layer4_info_t *l4) {
    
    memset(l4, 0, sizeof(layer4_info_t));
    l4->protocol = l3->protocol;
    
    // Calculate IP header end
    uint32_t offset = 14;  // Ethernet
    if (packet_len > 16) {
        uint16_t ethertype = ntohs(*(uint16_t *)(packet + 12));
        if (ethertype == 0x8100) offset = 18;  // VLAN
    }
    offset += l3->header_length;  // Skip IP header
    
    if (l3->protocol == IPPROTO_TCP) {
        // Parse TCP
        if (packet_len < offset + 20) return -1;
        
        struct tcphdr *tcp = (struct tcphdr *)(packet + offset);
        
        l4->src_port = ntohs(tcp->source);
        l4->dst_port = ntohs(tcp->dest);
        l4->seq_number = ntohl(tcp->seq);
        l4->ack_number = ntohl(tcp->ack_seq);
        l4->window_size = ntohs(tcp->window);
        l4->tcp_checksum = ntohs(tcp->check);
        l4->urgent_pointer = ntohs(tcp->urg_ptr);
        
        // Extract TCP flags
        l4->tcp_flags = 0;
        if (tcp->fin) l4->tcp_flags |= 0x01;
        if (tcp->syn) l4->tcp_flags |= 0x02;
        if (tcp->rst) l4->tcp_flags |= 0x04;
        if (tcp->psh) l4->tcp_flags |= 0x08;
        if (tcp->ack) l4->tcp_flags |= 0x10;
        if (tcp->urg) l4->tcp_flags |= 0x20;
        
    } else if (l3->protocol == IPPROTO_UDP) {
        // Parse UDP
        if (packet_len < offset + 8) return -1;
        
        struct udphdr *udp = (struct udphdr *)(packet + offset);
        
        l4->src_port = ntohs(udp->source);
        l4->dst_port = ntohs(udp->dest);
        l4->udp_length = ntohs(udp->len);
        l4->udp_checksum = ntohs(udp->check);
        
    } else if (l3->protocol == IPPROTO_ICMP) {
        // Parse ICMP
        if (packet_len < offset + 8) return -1;
        
        l4->icmp_type = packet[offset];
        l4->icmp_code = packet[offset + 1];
        l4->src_port = 0;
        l4->dst_port = 0;
    }
    
    return 0;
}

/* ========== Layer 5 Parsing (Flow Tracking) ========== */

void parse_layer5(const layer3_info_t *l3, const layer4_info_t *l4, 
                  layer5_info_t *l5) {
    
    // Copy 5-tuple
    l5->src_ip = l3->src_ip;
    l5->dst_ip = l3->dst_ip;
    l5->src_port = l4->src_port;
    l5->dst_port = l4->dst_port;
    l5->protocol = l3->protocol;
    
    // Determine flow state from TCP flags
    strcpy(l5->flow_state, "ESTABLISHED");
    l5->is_syn = 0;
    l5->is_ack = 0;
    l5->is_fin = 0;
    l5->is_rst = 0;
    
    if (l3->protocol == IPPROTO_TCP) {
        if (l4->tcp_flags & 0x02) {  // SYN
            l5->is_syn = 1;
            if (!(l4->tcp_flags & 0x10)) {  // SYN without ACK
                strcpy(l5->flow_state, "NEW");
            }
        }
        if (l4->tcp_flags & 0x10) l5->is_ack = 1;
        if (l4->tcp_flags & 0x01) {  // FIN
            l5->is_fin = 1;
            strcpy(l5->flow_state, "CLOSING");
        }
        if (l4->tcp_flags & 0x04) {  // RST
            l5->is_rst = 1;
            strcpy(l5->flow_state, "CLOSED");
        }
    }
}

/* ========== Main Packet Parser ========== */

int parse_packet(dpi_engine_t *engine, const uint8_t *packet, 
                 uint32_t packet_len, struct timeval ts, 
                 parsed_packet_t *parsed) {
    
    memset(parsed, 0, sizeof(parsed_packet_t));
    parsed->timestamp = ts;
    parsed->packet_size = packet_len;
    parsed->raw_data = packet;
    parsed->raw_data_len = packet_len;
    
    // Parse Layer 2
    if (parse_layer2(packet, packet_len, &parsed->layer2) == 0) {
        engine->l2_parsed++;
    } else {
        return -1;
    }
    
    // Parse Layer 3
    if (parse_layer3(packet, packet_len, &parsed->layer3) == 0) {
        engine->l3_parsed++;
    } else {
        return -1;
    }
    
    // Parse Layer 4
    if (parse_layer4(packet, packet_len, &parsed->layer3, &parsed->layer4) == 0) {
        engine->l4_parsed++;
    }
    
    // Parse Layer 5 (Flow tracking)
    parse_layer5(&parsed->layer3, &parsed->layer4, &parsed->layer5);
    
    // Get or create flow
    parsed->flow = get_or_create_flow(engine, &parsed->layer3, &parsed->layer4);
    
    // Update flow statistics
    if (parsed->flow) {
        update_flow_stats(parsed->flow, parsed);
    }
    
    // Detect protocol with nDPI (Layer 7 - partial)
    detect_protocol(engine, parsed);
    
    // Initialize MQTT fields (parsing happens AFTER attack detection)
    parsed->is_mqtt = 0;
    parsed->mqtt_packet_type = 0;
    parsed->mqtt_topic[0] = '\0';
    parsed->mqtt_client_id[0] = '\0';
    parsed->mqtt_payload_length = 0;
    parsed->mqtt_payload_data[0] = '\0';
    
    // Mark as potential MQTT but don't parse yet (security first!)
    if (parsed->layer4.dst_port == 1883 || parsed->layer4.src_port == 1883 ||
        parsed->layer4.dst_port == 8883 || parsed->layer4.src_port == 8883) {
        strcpy(parsed->detected_protocol, "MQTT-Port");  // Tentative
    }
    
    // Update global statistics
    engine->total_packets++;
    engine->total_bytes += packet_len;
    
    return 0;
}

/* This file continues in dpi_engine_flow.c for flow management functions */
