# 🔍 ATTACK DETECTION QUICK REFERENCE

## Attack Types & Detection Logic

### 1. SYN Flood Attack
```
SEVERITY:  HIGH
PROTOCOL:  TCP

Detection Logic:
  ✓ SYN packet rate > 100 packets/sec
  ✓ SYN:ACK ratio > 3:1
  ✓ High SYN count with few completed connections

Indicators:
  - syn_count > threshold
  - syn_count / ack_count > 3.0
  - Many connection attempts, few established

Example Metrics:
  SYN Count: 1000, ACK Count: 50 → ATTACK
  SYN Count: 100, ACK Count: 90 → NORMAL
```

### 2. UDP Flood Attack
```
SEVERITY:  HIGH
PROTOCOL:  UDP

Detection Logic:
  ✓ UDP packet rate > 200 packets/sec
  ✓ Total UDP packets > 1000
  ✓ Sustained high rate

Indicators:
  - udp_packet_rate > 200/sec
  - total_udp_packets > 1000
  - Duration > 10 seconds

Example Metrics:
  Rate: 300 pkt/sec, Total: 3000 → ATTACK
  Rate: 50 pkt/sec, Total: 500 → NORMAL
```

### 3. HTTP Flood Attack
```
SEVERITY:  HIGH
PROTOCOL:  TCP (Port 80/8080)

Detection Logic:
  ✓ HTTP request rate > 50 requests/sec
  ✓ Target is HTTP service (port 80/8080)
  ✓ Detected as HTTP by nDPI

Indicators:
  - request_rate > 50/sec
  - dst_port = 80 or 8080
  - protocol_name contains "HTTP"

Example Metrics:
  Rate: 75 req/sec to port 80 → ATTACK
  Rate: 25 req/sec to port 80 → NORMAL
```

### 4. Ping of Death
```
SEVERITY:  CRITICAL
PROTOCOL:  ICMP

Detection Logic:
  ✓ ICMP packet size > 65500 bytes
  ✓ Single oversized packet triggers detection

Indicators:
  - max_packet_size > 65500
  - protocol = ICMP (1)
  - Packet size exceeds maximum

Example Metrics:
  ICMP packet: 66000 bytes → ATTACK
  ICMP packet: 1500 bytes → NORMAL
```

### 5. ARP Spoofing
```
SEVERITY:  CRITICAL
PROTOCOL:  Layer 2 (ARP)

Detection Logic:
  ✓ Single IP uses 3+ different MAC addresses
  ✓ MAC address changes detected

Indicators:
  - ip_stats->mac_address_count >= 3
  - Multiple MACs for same IP
  - MAC changes over time

Example Metrics:
  IP: 192.168.1.10 with 4 MACs → ATTACK
  IP: 192.168.1.10 with 1 MAC → NORMAL
```

### 6. RUDY (Slow POST) Attack
```
SEVERITY:  MEDIUM
PROTOCOL:  TCP (HTTP)

Detection Logic:
  ✓ HTTP POST with very slow data rate
  ✓ Average rate < 10 bytes/sec
  ✓ Connection kept alive > 30 seconds

Indicators:
  - avg_data_rate < 10 bytes/sec
  - duration > 30 seconds
  - dst_port = 80/8080
  - min_packets = 10

Example Metrics:
  5 bytes/sec over 45 seconds → ATTACK
  500 bytes/sec over 10 seconds → NORMAL
```

### 7. TCP SYN Scan (Port Scanning)
```
SEVERITY:  MEDIUM
PROTOCOL:  TCP

Detection Logic:
  ✓ Many SYNs to different ports
  ✓ High RST count (no connection completion)
  ✓ Low ACK completion ratio

Indicators:
  - unique_dst_port_count >= 15
  - syn_count > 5
  - rst_count > 0
  - ack_count < syn_count * 0.3

Example Metrics:
  SYN to 20 ports, 15 RST, 3 ACK → ATTACK
  SYN to 2 ports, 0 RST, 2 ACK → NORMAL
```

### 8. TCP Connect Scan (Port Scanning)
```
SEVERITY:  MEDIUM
PROTOCOL:  TCP

Detection Logic:
  ✓ Full connections to many ports
  ✓ High connection completion ratio
  ✓ 15+ unique destination ports

Indicators:
  - unique_dst_port_count >= 15
  - completion_ratio > 0.8
  - Full 3-way handshake completed

Example Metrics:
  Connected to 20 ports, 18 completed → ATTACK
  Connected to 3 ports, 3 completed → NORMAL
```

### 9. UDP Scan (Port Scanning)
```
SEVERITY:  MEDIUM
PROTOCOL:  UDP

Detection Logic:
  ✓ Small UDP packets to many ports
  ✓ 20+ unique destination ports
  ✓ Average packet size < 100 bytes

Indicators:
  - unique_dst_port_count >= 20
  - avg_packet_size < 100 bytes
  - Probe packets (minimal data)

Example Metrics:
  30 ports, avg 50 bytes → ATTACK
  3 ports, avg 500 bytes → NORMAL
```

### 10. ICMP Flood
```
SEVERITY:  HIGH
PROTOCOL:  ICMP

Detection Logic:
  ✓ High rate of ICMP packets
  ✓ Rate > 100 packets/sec
  ✓ Sustained ICMP traffic

Indicators:
  - icmp_packet_rate > 100/sec
  - protocol = ICMP (1)
  - Duration > 10 seconds

Example Metrics:
  Rate: 150 ICMP/sec → ATTACK
  Rate: 10 ICMP/sec → NORMAL
```

## Detection Thresholds Summary

| Attack Type       | Primary Metric          | Threshold         |
|-------------------|-------------------------|-------------------|
| SYN Flood         | SYN packet rate         | 100 pkt/sec       |
| UDP Flood         | UDP packet rate         | 200 pkt/sec       |
| HTTP Flood        | HTTP request rate       | 50 req/sec        |
| Ping of Death     | ICMP packet size        | 65500 bytes       |
| ARP Spoofing      | MAC addresses per IP    | 3 MACs            |
| RUDY              | Data rate               | 10 bytes/sec      |
| TCP SYN Scan      | Unique ports            | 15 ports          |
| TCP Connect Scan  | Unique ports            | 15 ports          |
| UDP Scan          | Unique ports            | 20 ports          |
| ICMP Flood        | ICMP packet rate        | 100 pkt/sec       |

## Confidence Scoring

Each detection includes a confidence score (0.0 - 1.0):

- **0.9 - 1.0**: Very high confidence (e.g., Ping of Death, ARP Spoofing)
- **0.7 - 0.9**: High confidence (typical flood attacks)
- **0.5 - 0.7**: Medium confidence (port scans, RUDY)
- **0.3 - 0.5**: Low confidence (borderline cases)
- **< 0.3**: Very low confidence (possible false positive)

## Attack Severity Levels

```
🔴 CRITICAL (5/5)
   - Ping of Death
   - ARP Spoofing
   
🟠 HIGH (4/5)
   - SYN Flood
   - UDP Flood
   - HTTP Flood
   - ICMP Flood
   
🟡 MEDIUM (3/5)
   - RUDY (Slow POST)
   - TCP SYN Scan
   - TCP Connect Scan
   - UDP Scan
   
🟢 LOW (2/5)
   - (Reserved for future use)
   
⚪ INFO (1/5)
   - (Reserved for future use)
```

## Flow Statistics Used for Detection

The rule engine analyzes these flow metrics:

```c
// Connection metrics
syn_count              // TCP SYN packets
ack_count              // TCP ACK packets
fin_count              // TCP FIN packets
rst_count              // TCP RST packets

// Traffic volume
total_packets          // Total packet count
total_bytes            // Total byte count
packets_per_second     // Packet rate

// Port information
unique_dst_port_count  // Number of unique destination ports
unique_dst_ports[]     // List of accessed ports

// Packet characteristics
min_packet_size        // Smallest packet
max_packet_size        // Largest packet
avg_packet_size        // Average size

// Timing
duration_seconds       // Flow duration
inter_arrival_time     // Time between packets

// Protocol detection
protocol_name          // Detected by nDPI
```

## Command Examples

```bash
# Run analysis with default thresholds
./bin/dpi_engine_ids capture.pcap

# Generate detailed report
./bin/dpi_engine_ids capture.pcap full_report.txt

# Check specific attack types
grep "SYN Flood" full_report.txt
grep "Port Scan" full_report.txt

# Batch analysis
for pcap in *.pcap; do
    ./bin/dpi_engine_ids "$pcap" "report_$pcap.txt"
done
```

## Customizing Thresholds

Edit `src/rule_engine.c`, function `rule_engine_set_default_thresholds()`:

```c
// Make SYN flood detection more sensitive
t->syn_flood_threshold = 50;      // Lower threshold (was 100)
t->syn_flood_ratio = 2.0;         // Lower ratio (was 3.0)

// Make port scan detection less sensitive
t->port_scan_unique_ports = 50;   // Higher threshold (was 20)
```

Rebuild after changes:
```bash
make clean && make
```

## False Positive Mitigation

**If you see too many false positives:**

1. **Increase thresholds** - Make detection less sensitive
2. **Increase minimum packet counts** - Require more data
3. **Increase time windows** - Average over longer periods
4. **Add whitelist IPs** - Exclude trusted hosts (future enhancement)

**If you miss real attacks:**

1. **Decrease thresholds** - Make detection more sensitive
2. **Decrease minimum packet counts** - Trigger on less data
3. **Add more detection patterns** - Multiple indicators
4. **Lower confidence requirements** - Accept lower scores

---

**Quick Tip**: Start with default thresholds, then adjust based on your network's normal behavior.
