# Quick Start Guide

## Build (one time)
```bash
cd c_dpi_engine
make
```

## Run Analysis
```bash
./bin/dpi_mqtt_analyzer <pcap_file>
```

## Examples

### Analyze attack traffic
```bash
./bin/dpi_mqtt_analyzer ../scripts/attack_samples/syn_flood.pcap
./bin/dpi_mqtt_analyzer ../scripts/attack_samples/udp_flood.pcap
./bin/dpi_mqtt_analyzer ../scripts/attack_samples/tcp_syn_scan.pcap
```

### Analyze normal traffic
```bash
./bin/dpi_mqtt_analyzer ../scripts/pcap_samples/normal_mixed.pcap
./bin/dpi_mqtt_analyzer ../scripts/pcap_samples/test_100.pcap
```

## Output Reports

After each run, you get **4 detailed text files**:

### 1. performance_metrics.txt
- System overview and metrics summary
- DPI/IDS/MQTT performance
- Layer 2-5 parsing success rates
- Unique protocol detection count
- Processing time breakdown
- Detection accuracy (precision/recall/accuracy)

### 2. dpi_packets_detailed.txt
- Every packet with full layer details
- Layer 2: MAC addresses, EtherType
- Layer 3: IP addresses, protocol, TTL  
- Layer 4: Ports, TCP flags, UDP length
- Layer 5: Flow state (STATELESS/NEW/ESTABLISHED/CLOSING), packets/bytes/duration
- nDPI protocol detection
- Timestamps

### 3. dpi_flows_detailed.txt
- Complete 5-tuple for each flow
- Packets/bytes/duration statistics
- TCP details (SYN/FIN/RST counts, connection state)
- Protocol detection and category
- Sample packets

### 4. mqtt_packets_detailed.txt
- MQTT flow and packet statistics
- Packet type (CONNECT/PUBLISH/SUBSCRIBE/etc.)
- Payload hex dump + ASCII representation
- Topics, client IDs, message content
- Generated even when no MQTT traffic (with helpful info)

## View Reports
```bash
# Quick summary
cat performance_metrics.txt

# Packet details (all 5 layers)
less dpi_packets_detailed.txt

# Flow details  
less dpi_flows_detailed.txt

# MQTT payloads
less mqtt_packets_detailed.txt
```

That's it! Simple analysis with comprehensive reports.
