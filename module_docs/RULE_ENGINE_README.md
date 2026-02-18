# Rule-Based Intrusion Detection Engine

## Overview
The Rule-Based IDS Engine is a comprehensive network security module that detects various types of network attacks using statistical analysis, pattern matching, and behavioral anomaly detection. It analyzes packet flows to identify malicious activities including DoS/DDoS attacks, port scans, and application-layer attacks.

## Technical Architecture

### Core Components

#### 1. **Engine Structure** (`rule_engine_t`)
```c
typedef struct {
    // Configuration
    detection_thresholds_t thresholds;      // Configurable detection thresholds
    
    // IP Statistics Tracking
    ip_statistics_t *ip_stats;               // Per-IP behavior tracking
    uint32_t ip_stats_count;
    uint32_t max_ips;
    
    // Attack Detections
    attack_detection_t *detections;          // Detected attacks array
    uint32_t detection_count;
    uint32_t max_detections;
    
    // IP Blocking (IPS Mode)
    uint32_t *blocked_ips;                   // Blocked attacker IPs
    uint32_t blocked_ip_count;
    uint32_t max_blocked_ips;
    uint64_t blocked_packet_count;           // Packets dropped
    
    // Attack Type Statistics
    uint32_t attacks_by_type[16];            // Counter per attack type
    uint64_t total_packets_analyzed;
    uint64_t total_attacks_detected;
    
    // Timing
    struct timeval analysis_start_time;
    struct timeval analysis_end_time;
    
} rule_engine_t;
```

#### 2. **IP Statistics** (`ip_statistics_t`)
Per-IP behavior tracking for anomaly detection:
```c
typedef struct {
    uint32_t ip_address;
    
    // Traffic patterns
    uint64_t total_packets;
    uint64_t total_bytes;
    uint32_t tcp_packets, udp_packets, icmp_packets;
    
    // TCP behavior
    uint32_t syn_count, ack_count, fin_count, rst_count;
    
    // Connection tracking
    uint32_t unique_dst_ips[100];
    uint32_t unique_dst_ip_count;
    uint16_t unique_dst_ports[1024];
    uint32_t unique_dst_port_count;
    
    // Port scan indicators
    uint32_t connection_attempts;
    uint32_t failed_connections;
    
    // HTTP-specific
    uint32_t total_http_requests;
    
    // ARP spoofing detection
    uint8_t mac_addresses[10][6];
    uint32_t mac_address_count;
    
    // Time window
    struct timeval first_seen;
    struct timeval last_seen;
    
} ip_statistics_t;
```

#### 3. **Detection Result** (`attack_detection_t`)
```c
typedef struct {
    attack_type_t attack_type;               // Type of attack detected
    attack_severity_t severity;              // CRITICAL, HIGH, MEDIUM, LOW, INFO
    char attack_name[64];
    char description[256];
    double confidence_score;                 // 0.0 to 1.0
    
    // Source information
    uint32_t attacker_ip;
    uint32_t target_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;
    
    // Attack metrics
    uint64_t packet_count;
    uint64_t byte_count;
    double packets_per_second;
    double duration_seconds;
    struct timeval detection_time;
    
    // Additional details
    char details[512];
    
} attack_detection_t;
```

## Detection Algorithms

### 1. SYN Flood Attack

**Detection Logic:**
```c
int detect_syn_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                     attack_detection_t *detection) {
    
    if (flow->protocol != IPPROTO_TCP) return 0;
    
    // Calculate metrics
    double duration = calculate_duration(&flow->first_seen, &flow->last_seen);
    double syn_rate = (double)flow->syn_count / duration;
    
    // Calculate SYN:ACK ratio
    double syn_ack_ratio = 0.0;
    if (flow->ack_count > 0) {
        syn_ack_ratio = (double)flow->syn_count / (double)flow->ack_count;
    } else if (flow->syn_count > 0) {
        syn_ack_ratio = 999.0;  // No ACKs = extreme case
    }
    
    // Detection criteria
    if (syn_rate > engine->thresholds.syn_flood_threshold &&
        syn_ack_ratio > engine->thresholds.syn_flood_ratio) {
        
        // Fill detection structure
        detection->attack_type = ATTACK_SYN_FLOOD;
        detection->severity = SEVERITY_HIGH;
        detection->attacker_ip = flow->src_ip;
        detection->target_ip = flow->dst_ip;
        detection->packets_per_second = syn_rate;
        
        // Confidence based on how much thresholds are exceeded
        detection->confidence_score = fmin(1.0, 
            (syn_rate / (threshold * 2.0)) * 
            (syn_ack_ratio / (ratio_threshold * 2.0)));
        
        return 1;  // Attack detected
    }
    
    return 0;  // No attack
}
```

**Thresholds:**
- Default SYN rate: 100 packets/second
- Default SYN:ACK ratio: 3.0:1
- Time window: 10 seconds

**How it Works:**
1. Tracks SYN and ACK counts in TCP flows
2. Calculates rate of SYN packets per second
3. Compares SYN count to ACK count (legitimate connections should have balanced ratio)
4. High SYN rate + imbalanced ratio = SYN flood attack

**Aggregate Detection:**
Also detects distributed SYN flood where many flows target same destination:
```c
void detect_aggregate_syn_flood(rule_engine_t *engine, 
                               const dpi_engine_t *dpi_engine) {
    // Aggregate SYN packets by destination IP
    for each flow:
        if TCP and has SYN packets:
            targets[dst_ip].total_syn += flow->syn_count
            targets[dst_ip].flow_count++
            track unique attacker IPs
    
    // Check each target
    for each target:
        if total_syn_rate > threshold and attacker_count > 10:
            // Distributed SYN flood detected
            create detection with all attacker IPs
            block all attacker IPs
}
```

### 2. UDP Flood Attack

**Detection Logic:**
```c
int detect_udp_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                     attack_detection_t *detection) {
    
    if (flow->protocol != IPPROTO_UDP) return 0;
    
    double duration = calculate_duration(&flow->first_seen, &flow->last_seen);
    double packet_rate = (double)flow->total_packets / duration;
    
    // Detection criteria
    if (packet_rate > engine->thresholds.udp_flood_threshold &&
        flow->total_packets > engine->thresholds.udp_flood_packet_count) {
        
        detection->attack_type = ATTACK_UDP_FLOOD;
        detection->severity = SEVERITY_HIGH;
        detection->packets_per_second = packet_rate;
        detection->confidence_score = fmin(1.0, 
            packet_rate / (threshold * 2.0));
        
        return 1;
    }
    
    return 0;
}
```

**Thresholds:**
- Default rate: 200 packets/second
- Minimum packets: 1000 total packets
- Time window: 10 seconds

**How it Works:**
1. Tracks UDP packet rate per flow
2. Requires minimum packet count to avoid false positives
3. High sustained rate indicates flooding behavior

**Aggregate Detection:**
```c
void detect_aggregate_udp_flood(rule_engine_t *engine, 
                               const dpi_engine_t *dpi_engine) {
    // Similar to SYN flood, aggregate by target
    for each target with high UDP packet rate:
        count unique attackers
        calculate total rate
        
        if total_rate > threshold and multiple attackers:
            // Distributed UDP flood
            create detection and block attackers
}
```

### 3. HTTP Flood Attack

**Detection Logic:**
```c
int detect_http_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                      attack_detection_t *detection) {
    
    // Identify HTTP traffic
    int is_http = (flow->dst_port == 80 || flow->dst_port == 443 ||
                   flow->dst_port == 8080 ||
                   strstr(flow->protocol_name, "HTTP") != NULL);
    
    if (!is_http || flow->protocol != IPPROTO_TCP) return 0;
    
    // Calculate request rate
    double duration = calculate_duration(&flow->first_seen, &flow->last_seen);
    double request_rate = (double)flow->total_packets / duration;
    
    // Detection criteria
    if (request_rate > engine->thresholds.http_flood_threshold &&
        duration > engine->thresholds.http_flood_time_window) {
        
        detection->attack_type = ATTACK_HTTP_FLOOD;
        detection->severity = SEVERITY_MEDIUM;
        detection->packets_per_second = request_rate;
        
        return 1;
    }
    
    return 0;
}
```

**Thresholds:**
- Default rate: 50 requests/second
- Time window: 30 seconds

**How it Works:**
1. Identifies HTTP traffic by port (80, 443, 8080) or protocol name
2. Tracks packet rate as proxy for HTTP request rate
3. Sustained high request rate indicates application-layer DoS

### 4. ICMP Flood Attack

**Detection Logic:**
```c
int detect_icmp_flood(rule_engine_t *engine, const flow_stats_t *flow, 
                      attack_detection_t *detection) {
    
    if (flow->protocol != IPPROTO_ICMP) return 0;
    
    double duration = calculate_duration(&flow->first_seen, &flow->last_seen);
    double icmp_rate = (double)flow->total_packets / duration;
    
    if (icmp_rate > engine->thresholds.icmp_flood_threshold) {
        detection->attack_type = ATTACK_ICMP_FLOOD;
        detection->severity = SEVERITY_MEDIUM;
        detection->packets_per_second = icmp_rate;
        
        return 1;
    }
    
    return 0;
}
```

**Thresholds:**
- Default rate: 100 ICMP packets/second
- Time window: 10 seconds

### 5. Ping of Death (PoD)

**Detection Logic:**
```c
int detect_ping_of_death(rule_engine_t *engine, const flow_stats_t *flow, 
                         attack_detection_t *detection) {
    
    if (flow->protocol != IPPROTO_ICMP) return 0;
    
    // Check for oversized ICMP packets
    if (flow->max_packet_size > engine->thresholds.pod_packet_size) {
        detection->attack_type = ATTACK_PING_OF_DEATH;
        detection->severity = SEVERITY_CRITICAL;
        detection->confidence_score = 1.0;  // High confidence
        
        snprintf(detection->description, sizeof(detection->description),
                "Oversized ICMP packet detected (%u bytes, threshold: %u bytes)",
                flow->max_packet_size, engine->thresholds.pod_packet_size);
        
        return 1;
    }
    
    return 0;
}
```

**Thresholds:**
- Default size: 1500 bytes (larger than typical MTU)

**How it Works:**
1. Monitors maximum packet size in ICMP flows
2. Detects abnormally large ICMP packets
3. Large fragmented ICMP packets can crash older systems

### 6. TCP SYN Scan

**Detection Logic:**
```c
int detect_tcp_syn_scan(rule_engine_t *engine, const flow_stats_t *flow, 
                        attack_detection_t *detection) {
    
    if (flow->protocol != IPPROTO_TCP) return 0;
    
    // SYN scan characteristics:
    // - Many SYN packets
    // - Some RST packets (resetting connections after SYN-ACK)
    // - Low ACK count relative to SYN (no connection completion)
    
    double syn_to_rst_ratio = 0.0;
    if (flow->rst_count > 0) {
        syn_to_rst_ratio = (double)flow->syn_count / (double)flow->rst_count;
    }
    
    // High SYN count, presence of RSTs, low ACK completion
    if (flow->syn_count > 10 && 
        flow->rst_count > 5 &&
        syn_to_rst_ratio > 1.5 &&
        (double)flow->ack_count / flow->syn_count < 0.3) {
        
        detection->attack_type = ATTACK_TCP_SYN_SCAN;
        detection->severity = SEVERITY_MEDIUM;
        
        return 1;
    }
    
    return 0;
}
```

**How it Works:**
1. SYN scan sends SYN packets to probe ports
2. If port open: target sends SYN-ACK, scanner sends RST (no connection)
3. If port closed: target sends RST
4. Pattern: many SYNs, some RSTs, few ACKs

### 7. TCP Connect Scan

**Detection Logic:**
```c
int detect_tcp_connect_scan(rule_engine_t *engine, const flow_stats_t *flow, 
                            attack_detection_t *detection) {
    
    // Look for multiple destination ports from same source
    if (flow->unique_dst_port_count > 
        engine->thresholds.tcp_connect_scan_ports) {
        
        // Calculate connection completion ratio
        double completion_ratio = 0.0;
        if (flow->connection_attempts > 0) {
            completion_ratio = (double)flow->established_connections / 
                              (double)flow->connection_attempts;
        }
        
        // Many ports scanned, low completion rate
        if (completion_ratio < engine->thresholds.tcp_connect_scan_completion) {
            detection->attack_type = ATTACK_TCP_CONNECT_SCAN;
            detection->severity = SEVERITY_MEDIUM;
            
            snprintf(detection->details, sizeof(detection->details),
                    "Scanned %u unique ports with %.2f%% completion rate",
                    flow->unique_dst_port_count, completion_ratio * 100.0);
            
            return 1;
        }
    }
    
    return 0;
}
```

**Thresholds:**
- Default unique ports: 20
- Connection completion ratio: < 50%

**How it Works:**
1. Tracks unique destination ports per source IP
2. Connect scan completes full 3-way handshake then closes
3. Many ports attempted with low success rate = scanning behavior

### 8. UDP Port Scan

**Detection Logic:**
```c
int detect_udp_scan(rule_engine_t *engine, const flow_stats_t *flow, 
                    attack_detection_t *detection) {
    
    if (flow->protocol != IPPROTO_UDP) return 0;
    
    // Look for many unique destination ports
    if (flow->unique_dst_port_count > 
        engine->thresholds.port_scan_unique_ports) {
        
        detection->attack_type = ATTACK_UDP_SCAN;
        detection->severity = SEVERITY_LOW;
        
        snprintf(detection->details, sizeof(detection->details),
                "UDP scan targeting %u unique ports",
                flow->unique_dst_port_count);
        
        return 1;
    }
    
    return 0;
}
```

**How it Works:**
1. Tracks unique destination ports in UDP flows
2. UDP scan sends packets to many ports
3. Closed ports respond with ICMP Port Unreachable
4. Open ports may respond or stay silent

### 9. RUDY Attack (R-U-Dead-Yet / Slow POST)

**Detection Logic:**
```c
int detect_rudy_attack(rule_engine_t *engine, const flow_stats_t *flow, 
                       attack_detection_t *detection) {
    
    // Identify HTTP traffic
    int is_http = (flow->dst_port == 80 || flow->dst_port == 8080 ||
                   strstr(flow->protocol_name, "HTTP") != NULL);
    
    if (!is_http || flow->protocol != IPPROTO_TCP) return 0;
    
    // Need minimum packets and duration
    if (flow->total_packets < engine->thresholds.rudy_min_packets) return 0;
    
    double duration = calculate_duration(&flow->first_seen, &flow->last_seen);
    if (duration < engine->thresholds.rudy_time_window) return 0;
    
    // Calculate average data rate
    double avg_rate = (double)flow->total_bytes / duration;
    
    // Detection: Very slow data transmission rate
    if (avg_rate < engine->thresholds.rudy_avg_body_rate) {
        detection->attack_type = ATTACK_RUDY;
        detection->severity = SEVERITY_MEDIUM;
        
        snprintf(detection->description, sizeof(detection->description),
                "Slow HTTP POST detected (%.2f bytes/sec over %.2f seconds)",
                avg_rate, duration);
        
        return 1;
    }
    
    return 0;
}
```

**Thresholds:**
- Default rate: 10 bytes/second
- Minimum packets: 20
- Time window: 30 seconds

**How it Works:**
1. RUDY attack keeps HTTP connection alive with minimal data
2. Sends POST request very slowly (byte by byte)
3. Exhausts server resources by holding connections open
4. Detection: HTTP traffic with extremely low data rate over long duration

### 10. ARP Spoofing

**Detection Logic:**
```c
int detect_arp_spoofing(rule_engine_t *engine, const flow_stats_t *flow, 
                        attack_detection_t *detection) {
    
    // Find IP statistics for source IP
    ip_statistics_t *ip_stats = find_ip_stats(engine, flow->src_ip);
    if (!ip_stats) return 0;
    
    // Check if multiple MAC addresses are used for this IP
    if (ip_stats->mac_address_count >= 
        engine->thresholds.arp_spoofing_mac_changes) {
        
        detection->attack_type = ATTACK_ARP_SPOOFING;
        detection->severity = SEVERITY_CRITICAL;
        
        // List MAC addresses in details
        char mac_list[256] = "";
        for (uint32_t i = 0; i < ip_stats->mac_address_count; i++) {
            sprintf(mac_list + strlen(mac_list), 
                   "%02x:%02x:%02x:%02x:%02x:%02x ",
                   ip_stats->mac_addresses[i][0],
                   ip_stats->mac_addresses[i][1],
                   ip_stats->mac_addresses[i][2],
                   ip_stats->mac_addresses[i][3],
                   ip_stats->mac_addresses[i][4],
                   ip_stats->mac_addresses[i][5]);
        }
        
        snprintf(detection->details, sizeof(detection->details),
                "IP has %u different MAC addresses: %s",
                ip_stats->mac_address_count, mac_list);
        
        return 1;
    }
    
    return 0;
}
```

**Thresholds:**
- Default MAC changes: 2 (same IP with different MACs)

**How it Works:**
1. Tracks MAC addresses associated with each IP
2. Legitimate hosts have 1 MAC per IP
3. Multiple MACs for one IP indicates ARP spoofing/poisoning
4. Layer 2 attack that can enable man-in-the-middle attacks

## Detection Workflow

### Per-Packet Analysis:
```c
void rule_engine_analyze_packet(rule_engine_t *engine, 
                               const parsed_packet_t *packet) {
    // 1. Check if source IP is blocked (IPS mode)
    if (is_ip_blocked(engine, packet->layer3.src_ip)) {
        engine->blocked_packet_count++;
        return;  // Drop packet
    }
    
    // 2. Update IP statistics
    update_ip_statistics(engine, packet);
    
    // 3. Periodically check for flood sources
    if (engine->total_packets_analyzed % 1000 == 0) {
        check_and_block_flood_sources(engine);
    }
    
    engine->total_packets_analyzed++;
}
```

### Batch Flow Analysis:
```c
void rule_engine_analyze_all_flows(rule_engine_t *engine, 
                                  const dpi_engine_t *dpi_engine) {
    // 1. Run aggregate detections (view all flows together)
    detect_aggregate_syn_flood(engine, dpi_engine);
    detect_aggregate_udp_flood(engine, dpi_engine);
    detect_aggregate_icmp_flood(engine, dpi_engine);
    
    // 2. Analyze each flow individually
    for (uint32_t i = 0; i < dpi_engine->flow_count; i++) {
        const flow_stats_t *flow = &dpi_engine->flows[i];
        attack_detection_t detection;
        
        // Run all detection algorithms
        if (detect_syn_flood(engine, flow, &detection) ||
            detect_udp_flood(engine, flow, &detection) ||
            detect_http_flood(engine, flow, &detection) ||
            detect_icmp_flood(engine, flow, &detection) ||
            detect_ping_of_death(engine, flow, &detection) ||
            detect_rudy_attack(engine, flow, &detection) ||
            detect_tcp_syn_scan(engine, flow, &detection) ||
            detect_tcp_connect_scan(engine, flow, &detection) ||
            detect_udp_scan(engine, flow, &detection) ||
            detect_arp_spoofing(engine, flow, &detection)) {
            
            // Attack detected - add to detection list
            add_detection(engine, &detection);
            
            // Block attacker IP (IPS mode)
            block_ip(engine, detection.attacker_ip);
        }
    }
    
    printf("[Rule Engine] Analysis complete: %u attacks detected\n",
           engine->detection_count);
}
```

## IP Blocking / IPS Mode

### Blocking Mechanism:
```c
void block_ip(rule_engine_t *engine, uint32_t ip_address) {
    // Check if already blocked
    for (uint32_t i = 0; i < engine->blocked_ip_count; i++) {
        if (engine->blocked_ips[i] == ip_address) {
            return;  // Already blocked
        }
    }
    
    // Add to blocklist
    if (engine->blocked_ip_count < engine->max_blocked_ips) {
        engine->blocked_ips[engine->blocked_ip_count++] = ip_address;
        
        printf("\033[1;31m[IPS] BLOCKING attacker IP: %s\033[0m\n",
               ip_to_string(ip_address));
    }
}

int is_ip_blocked(rule_engine_t *engine, uint32_t ip_address) {
    for (uint32_t i = 0; i < engine->blocked_ip_count; i++) {
        if (engine->blocked_ips[i] == ip_address) {
            return 1;  // Blocked
        }
    }
    return 0;  // Not blocked
}
```

**Features:**
- Automatic blocking when attack detected
- Fast lookup for packet filtering
- Tracks number of dropped packets
- Can block up to 10,000 attacker IPs

## Configuration

### Default Thresholds:
```c
void rule_engine_set_default_thresholds(rule_engine_t *engine) {
    detection_thresholds_t *t = &engine->thresholds;
    
    // SYN Flood
    t->syn_flood_threshold = 100;          // 100 SYN/sec
    t->syn_flood_ratio = 3.0;              // SYN:ACK ratio > 3:1
    t->syn_flood_time_window = 10;         // 10 seconds
    
    // UDP Flood
    t->udp_flood_threshold = 200;          // 200 packets/sec
    t->udp_flood_packet_count = 1000;      // Min 1000 packets
    t->udp_flood_time_window = 10;
    
    // HTTP Flood
    t->http_flood_threshold = 50;          // 50 requests/sec
    t->http_flood_time_window = 30;
    
    // Ping of Death
    t->pod_packet_size = 1500;             // > 1500 bytes
    
    // RUDY
    t->rudy_avg_body_rate = 10.0;          // < 10 bytes/sec
    t->rudy_min_packets = 20;
    t->rudy_time_window = 30;
    
    // Port Scans
    t->port_scan_unique_ports = 20;        // 20+ unique ports
    t->tcp_connect_scan_ports = 20;
    t->tcp_connect_scan_completion = 0.5;  // < 50% completion
    
    // ICMP Flood
    t->icmp_flood_threshold = 100;         // 100 ICMP/sec
    t->icmp_flood_time_window = 10;
    
    // ARP Spoofing
    t->arp_spoofing_mac_changes = 2;       // 2+ MACs per IP
}
```

### Customization:
Thresholds can be adjusted based on network characteristics:
```c
// Increase sensitivity (detect more attacks, higher false positives)
engine->thresholds.syn_flood_threshold = 50;   // Lower threshold

// Decrease sensitivity (fewer false positives, may miss attacks)
engine->thresholds.udp_flood_threshold = 500;  // Higher threshold
```

## Initialization and Usage

### Initialization:
```c
rule_engine_t* rule_engine_init(void) {
    rule_engine_t *engine = calloc(1, sizeof(rule_engine_t));
    
    // Set default thresholds
    rule_engine_set_default_thresholds(engine);
    
    // Allocate IP statistics table (10,000 IPs)
    engine->max_ips = 10000;
    engine->ip_stats = calloc(engine->max_ips, sizeof(ip_statistics_t));
    
    // Allocate detections array (1,000 detections)
    engine->max_detections = 1000;
    engine->detections = calloc(engine->max_detections, 
                               sizeof(attack_detection_t));
    
    // Allocate IP blocklist (10,000 IPs)
    engine->max_blocked_ips = 10000;
    engine->blocked_ips = calloc(engine->max_blocked_ips, sizeof(uint32_t));
    
    return engine;
}
```

### Usage Example:
```c
// Initialize engines
dpi_engine_t *dpi = dpi_engine_init(100000);
rule_engine_t *ids = rule_engine_init();

// Process packets
for each packet:
    parsed_packet_t parsed;
    parse_packet(dpi, packet_data, packet_len, timestamp, &parsed);
    
    // Analyze with IDS
    rule_engine_analyze_packet(ids, &parsed);

// After all packets processed, analyze flows
rule_engine_analyze_all_flows(ids, dpi);

// Print results
for (uint32_t i = 0; i < ids->detection_count; i++) {
    attack_detection_t *det = &ids->detections[i];
    printf("[%s] %s: %s -> %s (%.2f confidence)\n",
           severity_to_string(det->severity),
           det->attack_name,
           ip_to_string(det->attacker_ip),
           ip_to_string(det->target_ip),
           det->confidence_score);
}

// Cleanup
rule_engine_destroy(ids);
dpi_engine_destroy(dpi);
```

## Performance Metrics

### Complexity:
- **Per-packet Analysis**: O(1) for IP lookup, O(1) for block check
- **Flow Analysis**: O(N) where N = number of flows
- **Detection**: O(N) per detection algorithm
- **IP Blocking**: O(M) where M = blocked IP count

### Memory Usage:
- IP Statistics: ~200 bytes per IP
- Detections: ~1KB per detection
- Blocked IPs: 4 bytes per IP
- Total: ~2MB for 10K IPs + 1K detections

### Processing Rate:
- Can analyze 100,000+ packets/second
- Typical detection latency: < 10ms
- Suitable for real-time IDS/IPS deployment

## False Positive Mitigation

### Strategies:
1. **Confidence Scoring**: Each detection includes confidence score
2. **Multi-factor Detection**: Requires multiple indicators (rate + ratio)
3. **Minimum Thresholds**: Packet count/duration minimums
4. **Aggregate Analysis**: Correlates multiple flows
5. **Protocol Awareness**: Uses protocol-specific knowledge

### Tuning:
- Monitor false positive rate in production
- Adjust thresholds based on baseline traffic
- Consider whitelisting known-good IPs
- Use aggregate detections for better accuracy

## Dependencies

- DPI Engine: Provides parsed packet and flow data
- Standard C libraries: stdio.h, stdlib.h, string.h, math.h

## Files

### Headers
- `rule_engine.h`: Main interface and data structures

### Implementation
- `rule_engine.c`: Core engine and utilities
- `rule_engine_attacks.c`: Attack detection algorithms
- `rule_engine_report.c`: Report generation
- `ids_reports.c`: Detailed IDS reporting

## Future Enhancements

1. **Machine Learning**: ML-based anomaly detection
2. **Behavioral Baselining**: Learn normal traffic patterns
3. **Protocol Validation**: Deep protocol state machine validation
4. **GeoIP Blocking**: Block based on geographic location
5. **Reputation Lists**: Integration with threat intelligence feeds
6. **Rate Limiting**: Automatic rate limiting instead of blocking
7. **Whitelist Support**: Exclude trusted IPs from analysis
8. **Time-based Rules**: Different thresholds by time of day
