/*
 * IWSN Security - DPI Engine Header
 * Complete packet parsing (Layer 2-5) + nDPI (Layer 7 partial)
 */

#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_typedefs.h>
#include <ndpi/ndpi_protocol_ids.h>

/* ========== Layer 2 (Data Link) Structures ========== */
typedef struct {
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ethertype;
    uint16_t vlan_id;
    uint8_t has_vlan;
} layer2_info_t;

/* ========== Layer 3 (Network) Structures ========== */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t protocol;
    uint8_t ttl;
    uint16_t packet_size;
    uint16_t header_length;
    uint16_t flags;
    uint16_t fragment_offset;
    uint16_t identification;
    uint16_t checksum;
    uint8_t version;
} layer3_info_t;

/* ========== Layer 4 (Transport) Structures ========== */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;  // TCP=6, UDP=17, ICMP=1
    
    // TCP specific
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t tcp_flags;
    uint16_t window_size;
    uint16_t tcp_checksum;
    uint16_t urgent_pointer;
    
    // UDP specific
    uint16_t udp_length;
    uint16_t udp_checksum;
    
    // ICMP specific
    uint8_t icmp_type;
    uint8_t icmp_code;
} layer4_info_t;

/* ========== Layer 5 (Session) - Flow Tracking ========== */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    // Flow state
    char flow_state[20];  // NEW, ESTABLISHED, CLOSING, CLOSED
    uint8_t is_syn;
    uint8_t is_ack;
    uint8_t is_fin;
    uint8_t is_rst;
} layer5_info_t;

/* ========== Forward declaration ========== */
struct parsed_packet_s;

/* ========== Flow Statistics ========== */
typedef struct {
    // Flow identification (5-tuple)
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    // Timestamps
    struct timeval first_seen;
    struct timeval last_seen;
    
    // Packet storage for this flow
    struct parsed_packet_s **packets;
    uint32_t packet_count_stored;
    uint32_t packet_capacity;
    
    // Packet counts
    uint64_t total_packets;
    uint64_t packets_src_to_dst;
    uint64_t packets_dst_to_src;
    
    // Byte counts
    uint64_t total_bytes;
    uint64_t bytes_src_to_dst;
    uint64_t bytes_dst_to_src;
    
    // TCP specific
    uint32_t syn_count;
    uint32_t ack_count;
    uint32_t fin_count;
    uint32_t rst_count;
    
    // Connection tracking
    uint32_t connection_attempts;
    uint32_t established_connections;
    
    // Port tracking
    uint16_t unique_dst_ports[1024];
    uint16_t unique_dst_port_count;
    
    // Packet sizes
    uint32_t min_packet_size;
    uint32_t max_packet_size;
    uint64_t total_packet_size;
    
    // Inter-arrival times (in microseconds)
    uint64_t last_packet_time_us;
    uint64_t total_inter_arrival_time;
    uint32_t inter_arrival_count;
    
    // nDPI flow structure (5.x uses only flow struct)
    struct ndpi_flow_struct *ndpi_flow;
    
    // Detected protocol
    ndpi_protocol detected_protocol;
    char protocol_name[64];
    
    // Protocol voting - track protocol detections per flow
    char candidate_protocols[10][64];  // Store up to 10 different detected protocols
    uint32_t protocol_counts[10];      // Count of packets for each protocol
    uint32_t num_candidates;           // Number of unique protocols detected
    uint8_t protocol_confirmed;        // Flag: protocol confirmed with 5+ packets
    
} flow_stats_t;

/* ========== Parsed Packet Structure ========== */
typedef struct parsed_packet_s {
    struct timeval timestamp;
    uint32_t packet_size;
    uint32_t packet_number;
    
    // Layer information
    layer2_info_t layer2;
    layer3_info_t layer3;
    layer4_info_t layer4;
    layer5_info_t layer5;
    
    // Protocol detection (Layer 7 - partial)
    char detected_protocol[64];
    
    // MQTT packet information (if applicable)
    uint8_t is_mqtt;
    uint8_t mqtt_packet_type;
    char mqtt_topic[256];
    char mqtt_client_id[256];
    uint32_t mqtt_payload_length;
    char mqtt_payload_data[512];  // Actual payload content
    
    // Pointer to raw packet data
    const uint8_t *raw_data;
    uint32_t raw_data_len;
    
    // Flow statistics pointer
    flow_stats_t *flow;
    
} parsed_packet_t;

/* ========== DPI Engine Context ========== */
typedef struct {
    // nDPI detection module
    struct ndpi_detection_module_struct *ndpi;
    
    // Flow hash table (simple hash table for now)
    flow_stats_t *flows;
    uint32_t flow_count;
    uint32_t max_flows;
    
    // Capture format
    int datalink_type;  // DLT_EN10MB, DLT_LINUX_SLL, or DLT_LINUX_SLL2
    
    // Statistics
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t l2_parsed;
    uint64_t l3_parsed;
    uint64_t l4_parsed;
    uint64_t l5_parsed;
    uint64_t flows_created;
    
} dpi_engine_t;

/* ========== PCAP File Statistics ========== */
typedef struct {
    char filename[256];
    uint64_t file_size;
    uint32_t total_packets;
    uint32_t total_flows;
    uint64_t total_bytes;
    struct timeval start_time;
    struct timeval end_time;
    double duration_seconds;
    uint32_t min_packet_size;
    uint32_t max_packet_size;
    double avg_packet_size;
    int datalink_type;  // Store datalink type (DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2)
} pcap_stats_t;

/* ========== Function Prototypes ========== */

// Engine initialization
dpi_engine_t* dpi_engine_init(uint32_t max_flows);
void dpi_engine_destroy(dpi_engine_t *engine);

// Packet parsing
int parse_packet(dpi_engine_t *engine, const uint8_t *packet, 
                 uint32_t packet_len, struct timeval ts, 
                 parsed_packet_t *parsed);

// Layer parsing functions
int parse_layer2(const uint8_t *packet, uint32_t packet_len, 
                 layer2_info_t *l2);
int parse_layer3(const uint8_t *packet, uint32_t packet_len, 
                 layer3_info_t *l3);
int parse_layer4(const uint8_t *packet, uint32_t packet_len, 
                 const layer3_info_t *l3, layer4_info_t *l4);
void parse_layer5(const layer3_info_t *l3, const layer4_info_t *l4, 
                  layer5_info_t *l5);

// Flow management
flow_stats_t* get_or_create_flow(dpi_engine_t *engine, 
                                  const layer3_info_t *l3,
                                  const layer4_info_t *l4);
void update_flow_stats(flow_stats_t *flow, const parsed_packet_t *parsed);

// nDPI integration
void detect_protocol(dpi_engine_t *engine, parsed_packet_t *parsed);

// Utility functions
void print_packet_info(const parsed_packet_t *parsed);
void print_flow_stats(const flow_stats_t *flow);
void print_mac_address(const uint8_t *mac);
void print_ip_address(uint32_t ip);
void format_timestamp(const struct timeval *ts, char *buffer, size_t buf_size);
const char* get_protocol_name(uint8_t protocol);

// PCAP file processing
int process_pcap_file(const char *filename, dpi_engine_t *engine, pcap_stats_t *stats);
void print_pcap_summary(const pcap_stats_t *stats);
void print_flow_with_packets(const flow_stats_t *flow, uint32_t flow_num);
void store_packet_in_flow(flow_stats_t *flow, const parsed_packet_t *parsed);

#endif /* DPI_ENGINE_H */
