/*
 * DPI Engine - Main Implementation
 * Complete Layer 2-5 parsing + nDPI for Layer 7 protocol detection
 * Integrated with MQTT parser for deep application layer analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
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
                // Free raw packet data if allocated
                if (engine->flows[i].packets[j] && engine->flows[i].packets[j]->raw_data) {
                    free((void*)engine->flows[i].packets[j]->raw_data);
                }
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

// Parse LINUX_SLL2 format (used by tcpdump on Linux when capturing on "any" interface)
int parse_linux_sll2(const uint8_t *packet, uint32_t packet_len, layer2_info_t *l2, uint32_t *ip_offset) {
    if (packet_len < 20) return -1;
    
    // LINUX_SLL2 header structure:
    // 0-1: Protocol type
    // 2-3: Reserved (MBZ)
    // 4-7: Interface index
    // 8-9: ARPHRD type
    // 10: Packet type
    // 11: Link-layer address length
    // 12-19: Link-layer address (8 bytes)
    // 20+: Protocol header
    
    uint16_t proto_type = (packet[0] << 8) | packet[1];
    
    // Clear MAC addresses for SLL2 (not always available)
    memset(l2->src_mac, 0, 6);
    memset(l2->dst_mac, 0, 6);
    
    // Extract link-layer address if available (usually MAC address for Ethernet)
    uint8_t addr_len = packet[11];
    if (addr_len >= 6) {
        memcpy(l2->src_mac, packet + 12, 6);
    }
    
    // Protocol type at offset 0-1 is the EtherType
    l2->ethertype = proto_type;
    l2->has_vlan = 0;
    l2->vlan_id = 0;
    
    *ip_offset = 20;  // IP header starts after SLL2 header
    return 0;
}

// Parse LINUX_SLL format (older version)
int parse_linux_sll(const uint8_t *packet, uint32_t packet_len, layer2_info_t *l2, uint32_t *ip_offset) {
    if (packet_len < 16) return -1;
    
    // LINUX_SLL header: 16 bytes
    // Protocol type is at offset 14-15
    uint16_t proto_type = (packet[14] << 8) | packet[15];
    
    memset(l2->src_mac, 0, 6);
    memset(l2->dst_mac, 0, 6);
    
    // Extract link-layer address if available
    uint8_t addr_len = packet[4];
    if (addr_len >= 6 && packet_len >= 6 + 8) {
        memcpy(l2->src_mac, packet + 6, 6);
    }
    
    l2->ethertype = proto_type;
    l2->has_vlan = 0;
    l2->vlan_id = 0;
    
    *ip_offset = 16;  // IP header starts after SLL header
    return 0;
}

int parse_layer2(const uint8_t *packet, uint32_t packet_len, layer2_info_t *l2) {
    if (packet_len < 14) {
        return -1;  // Too short for any header
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

int parse_layer3_with_offset(const uint8_t *packet, uint32_t packet_len, uint32_t offset, layer3_info_t *l3) {
    // Check if we have enough data for IP header
    if (packet_len < offset + 20) {
        return -1;  // Too short for IP header
    }
    
    // Check IP version from first byte
    uint8_t version = (packet[offset] >> 4) & 0x0F;
    
    if (version == 4) {
        // IPv4 packet
        struct iphdr *ip = (struct iphdr *)(packet + offset);
        
        // Extract IP header fields
        l3->src_ip = ntohl(ip->saddr);
        l3->dst_ip = ntohl(ip->daddr);
        l3->protocol = ip->protocol;
        l3->ttl = ip->ttl;
        l3->packet_size = ntohs(ip->tot_len);
        l3->header_length = ip->ihl * 4;
        l3->identification = ntohs(ip->id);
        l3->checksum = ntohs(ip->check);
        l3->version = ip->version;
        
        // Extract flags and fragment offset
        uint16_t frag = ntohs(ip->frag_off);
        l3->flags = (frag >> 13) & 0x07;
        l3->fragment_offset = frag & 0x1FFF;
        
        return 0;
    } else if (version == 6) {
        // IPv6 packet - currently not fully supported, mark and skip
        // TODO: Add full IPv6 support
        l3->version = 6;
        l3->protocol = packet[offset + 6];  // Next Header field
        l3->ttl = packet[offset + 7];       // Hop Limit
        l3->header_length = 40;             // IPv6 header is fixed 40 bytes
        
        // For now, set IPs to 0 (would need 128-bit address support)
        l3->src_ip = 0;
        l3->dst_ip = 0;
        l3->packet_size = ntohs(*(uint16_t *)(packet + offset + 4)) + 40;
        
        return -1;  // Return -1 to skip IPv6 for now
    }
    
    return -1;  // Unknown IP version
}

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
    
    return parse_layer3_with_offset(packet, packet_len, offset, l3);
}

/* ========== Layer 4 Parsing ========== */

int parse_layer4_with_offset(const uint8_t *packet, uint32_t packet_len, uint32_t l2_offset, 
                              const layer3_info_t *l3, layer4_info_t *l4) {
    memset(l4, 0, sizeof(layer4_info_t));
    l4->protocol = l3->protocol;
    
    // Calculate Layer 4 offset
    uint32_t offset = l2_offset + l3->header_length;
    
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

int parse_layer4(const uint8_t *packet, uint32_t packet_len, 
                 const layer3_info_t *l3, layer4_info_t *l4) {
    uint32_t l2_offset = 14;  // Standard Ethernet
    if (packet_len > 16) {
        uint16_t ethertype = ntohs(*(uint16_t *)(packet + 12));
        if (ethertype == 0x8100) l2_offset = 18;  // VLAN
    }
    return parse_layer4_with_offset(packet, packet_len, l2_offset, l3, l4);
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
    l5->is_syn = 0;
    l5->is_ack = 0;
    l5->is_fin = 0;
    l5->is_rst = 0;
    
    if (l3->protocol == IPPROTO_TCP) {
        // TCP connections have state
        strcpy(l5->flow_state, "ESTABLISHED");
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
    } else {
        // UDP, ICMP, and other protocols are stateless
        strcpy(l5->flow_state, "STATELESS");
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
    
    // Parse Layer 2 - handle different capture formats
    uint32_t ip_offset = 0;
    
    if (engine->datalink_type == DLT_LINUX_SLL2) {
        // Linux cooked capture v2
        if (parse_linux_sll2(packet, packet_len, &parsed->layer2, &ip_offset) == 0) {
            engine->l2_parsed++;
        } else {
            return -1;
        }
    } else if (engine->datalink_type == DLT_LINUX_SLL) {
        // Linux cooked capture v1
        if (parse_linux_sll(packet, packet_len, &parsed->layer2, &ip_offset) == 0) {
            engine->l2_parsed++;
        } else {
            return -1;
        }
    } else {
        // Standard Ethernet (DLT_EN10MB)
        if (parse_layer2(packet, packet_len, &parsed->layer2) == 0) {
            engine->l2_parsed++;
            ip_offset = 14;
            if (parsed->layer2.has_vlan) ip_offset = 18;
        } else {
            return -1;
        }
    }
    
    // Parse Layer 3 - pass the correct offset
    if (parse_layer3_with_offset(packet, packet_len, ip_offset, &parsed->layer3) == 0) {
        engine->l3_parsed++;
    } else {
        return -1;
    }
    
    // Parse Layer 4
    if (parse_layer4_with_offset(packet, packet_len, ip_offset, &parsed->layer3, &parsed->layer4) == 0) {
        engine->l4_parsed++;
    }
    
    // Parse Layer 5 (Flow tracking)
    parse_layer5(&parsed->layer3, &parsed->layer4, &parsed->layer5);
    engine->l5_parsed++;
    
    // Get or create flow
    parsed->flow = get_or_create_flow(engine, &parsed->layer3, &parsed->layer4);
    
    // Update flow statistics
    if (parsed->flow) {
        update_flow_stats(parsed->flow, parsed);
    }
    
    // Initialize MQTT fields (parsing happens AFTER attack detection)
    parsed->is_mqtt = 0;
    parsed->mqtt_packet_type = 0;
    parsed->mqtt_topic[0] = '\0';
    parsed->mqtt_client_id[0] = '\0';
    parsed->mqtt_payload_length = 0;
    parsed->mqtt_payload_data[0] = '\0';
    
    // Port-based protocol detection (custom parser has priority over nDPI)
    // This helps when nDPI can't detect encrypted or simple protocols
    uint16_t src_port = parsed->layer4.src_port;
    uint16_t dst_port = parsed->layer4.dst_port;
    
    if (dst_port == 1883 || src_port == 1883 || dst_port == 8883 || src_port == 8883) {
        strcpy(parsed->detected_protocol, "MQTT");
    } else if (dst_port == 53 || src_port == 53) {
        strcpy(parsed->detected_protocol, "DNS");
    } else if (dst_port == 5353 || src_port == 5353) {
        strcpy(parsed->detected_protocol, "mDNS");
    } else if (dst_port == 80 || src_port == 80) {
        strcpy(parsed->detected_protocol, "HTTP");
    } else if (dst_port == 443 || src_port == 443) {
        strcpy(parsed->detected_protocol, "TLS");
    } else if (dst_port == 22 || src_port == 22) {
        strcpy(parsed->detected_protocol, "SSH");
    } else if (dst_port == 21 || src_port == 21) {
        strcpy(parsed->detected_protocol, "FTP");
    } else if (dst_port == 20 || src_port == 20) {
        strcpy(parsed->detected_protocol, "FTP-Data");
    } else if (dst_port == 25 || src_port == 25) {
        strcpy(parsed->detected_protocol, "SMTP");
    } else if (dst_port == 110 || src_port == 110) {
        strcpy(parsed->detected_protocol, "POP3");
    } else if (dst_port == 143 || src_port == 143) {
        strcpy(parsed->detected_protocol, "IMAP");
    } else if (dst_port == 3306 || src_port == 3306) {
        strcpy(parsed->detected_protocol, "MySQL");
    } else if (dst_port == 5432 || src_port == 5432) {
        strcpy(parsed->detected_protocol, "PostgreSQL");
    } else if (dst_port == 6379 || src_port == 6379) {
        strcpy(parsed->detected_protocol, "Redis");
    } else if (dst_port == 27017 || src_port == 27017) {
        strcpy(parsed->detected_protocol, "MongoDB");
    }
    
    // Detect protocol with nDPI (Layer 7 - partial)
    // This will use custom parser result if already set, otherwise fall back to nDPI
    detect_protocol(engine, parsed);
    
    // Update global statistics
    engine->total_packets++;
    engine->total_bytes += packet_len;
    
    return 0;
}

/* This file continues in dpi_engine_flow.c for flow management functions */
