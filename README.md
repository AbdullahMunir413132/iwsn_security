# IWSN Security - Deep Packet Inspection & Intrusion Detection System

A comprehensive network security analysis system with DPI (Deep Packet Inspection), IDS (Intrusion Detection), and MQTT protocol analysis. Generates detailed text reports for network traffic analysis.

## Features

- **DPI Engine**: Complete packet parsing (Layer 2-5) with nDPI protocol detection
- **IDS/Rule Engine**: Attack detection (SYN flood, UDP flood, HTTP flood, port scans, etc.)
- **MQTT Parser**: IoT/MQTT protocol analysis with payload extraction
- **Performance Metrics**: Comprehensive performance tracking with detailed text reports
- **Flow Tracking**: TCP state tracking (NEW, ESTABLISHED, CLOSING) and UDP/ICMP stateless flows

## Quick Start

### Build
```bash
cd c_dpi_engine
make clean && make
```

### Run Analysis
```bash
./bin/dpi_mqtt_analyzer <pcap_file>
```

Example:
```bash
./bin/dpi_mqtt_analyzer ../scripts/attack_samples/syn_flood.pcap
```

## Output

Each analysis generates **four detailed text reports**:

### 1. performance_metrics.txt
Comprehensive performance report including:
- System overview (PCAP file, duration, total packets/flows)
- DPI Engine metrics (Layer 2-5 parsing rates, unique protocol detection)
- Rule Engine/IDS metrics (attack detection, precision, recall, accuracy)
- MQTT Parser metrics (message parsing, sensor data extraction)
- Processing time breakdown per component
- Detection accuracy table (TP/FP/TN/FN)
- System-wide performance (throughput, processing time)

### 2. dpi_packets_detailed.txt
**Packet-by-packet analysis** with full details:
- **Layer 2 (Data Link)**: Source/Dest MAC addresses, EtherType, VLAN
- **Layer 3 (Network)**: Source/Dest IP, protocol, TTL, packet size, IP version
- **Layer 4 (Transport)**: 
  - TCP: Source/Dest ports, flags (SYN/ACK/FIN/RST/PSH), sequence/ack numbers, window size
  - UDP: Source/Dest ports, length
- **Layer 5 (Session/Flow)**: Flow state (STATELESS/NEW/ESTABLISHED/CLOSING/CLOSED), packet count, bytes, duration
- **Protocol Detection**: nDPI detected protocol name
- **Timestamps**: Precise packet capture time
- Organized by flow with all packets shown

### 3. dpi_flows_detailed.txt
**Flow-by-flow analysis** with statistics:
- **Flow Identification**: Complete 5-tuple (src/dst IP:port, protocol)
- **Flow Statistics**: Total packets/bytes, first/last seen, duration, throughput (packets/sec, bytes/sec)
- **TCP Flow Details**: SYN/FIN/RST packet counts, connection state
- **Protocol Detection**: nDPI protocol name and traffic category
- **Sample Packets**: First 5 packets from each flow with key details

### 4. mqtt_packets_detailed.txt
**MQTT-specific analysis** with payload details:
- **MQTT Flow Statistics**: Total MQTT flows and packets detected
- **Packet Details**: Packet type (CONNECT/PUBLISH/SUBSCRIBE/PINGREQ/DISCONNECT)
- **Payload Extraction**: Full payload hex dump with ASCII representation
- **Topic & Client Info**: MQTT topics, client IDs, message content
- **No-Traffic Handling**: Informative message when no MQTT traffic detected

## Project Structure

```
iwsn_security/
├── c_dpi_engine/          # DPI & IDS engine (C)
│   ├── bin/               # Compiled binaries
│   ├── src/               # Source code
│   ├── include/           # Header files
│   └── Makefile           # Build configuration
├── scripts/               # PCAP samples
│   ├── pcap_samples/      # Normal traffic
│   └── attack_samples/    # Attack traffic
└── docs/                  # Documentation
```

## Available Analyzers

- **dpi_mqtt_analyzer**: Full analysis (DPI → IDS → MQTT Parser) with performance metrics
- **dpi_engine_ids**: DPI with IDS/attack detection only
- **dpi_engine**: Basic DPI analysis only

## Sample PCAP Files

### Normal Traffic
- `scripts/pcap_samples/normal_mixed.pcap` - Mixed protocols
- `scripts/pcap_samples/realmqtt.pcap` - MQTT traffic

### Attack Samples
- `scripts/attack_samples/syn_flood.pcap` - SYN flood attack
- `scripts/attack_samples/udp_flood.pcap` - UDP flood attack
- `scripts/attack_samples/tcp_syn_scan.pcap` - TCP SYN port scan
- `scripts/attack_samples/http_flood.pcap` - HTTP flood attack
- `scripts/attack_samples/ping_of_death.pcap` - Ping of Death
- `scripts/attack_samples/icmp_flood.pcap` - ICMP flood

## Key Metrics Tracked

### DPI Engine
- Layer 2/3/4/5 parsing success rates (100% shown for each layer)
- Unique protocol type detection (counts distinct protocols, not flows)
- Processing throughput (packets/sec, MB/sec)
- Per-packet and per-flow processing time

### IDS/Rule Engine
- Total attacks detected (by type: SYN flood, UDP flood, scans, etc.)
- Detection accuracy (precision, recall, accuracy)
- True/False Positive/Negative counts
- Flows analyzed and processing speed

### MQTT Parser
- MQTT flows detected
- Messages parsed successfully
- Sensor data extracted
- Parsing accuracy

### System Performance
- Total processing time
- CPU usage
- Memory utilization
- Overall throughput

## Requirements

- **gcc** (GCC 7.0 or higher)
- **libpcap** - Packet capture library
- **nDPI** - Network protocol detection library (v5.1.0+)
- **Paho MQTT C** - MQTT client library
- **libm** - Math library

See [docs/INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md) for installation instructions.

## Documentation

- **Installation**: [docs/INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md)
- **Architecture**: [docs/TECHNICAL_ARCHITECTURE_GUIDE.md](docs/TECHNICAL_ARCHITECTURE_GUIDE.md)
- **Attack Detection**: [docs/ATTACK_DETECTION_REFERENCE.md](docs/ATTACK_DETECTION_REFERENCE.md)
- **Performance Metrics**: [docs/PERFORMANCE_METRICS_GUIDE.md](docs/PERFORMANCE_METRICS_GUIDE.md)

## Recent Improvements

✅ **Layer 5 Metrics** - Complete flow tracking with session state (NEW/ESTABLISHED/CLOSING/STATELESS)  
✅ **MQTT Payload Reports** - Detailed MQTT packet analysis with hex/ASCII payload dumps  
✅ **Unique Protocol Counting** - Fixed to count distinct protocol types, not total flows  
✅ **Flow State Logic** - TCP shows proper states, UDP/ICMP correctly marked STATELESS  
✅ **Detailed Packet & Flow Reports** - Packet-by-packet and flow-by-flow text reports with all layers  
✅ **Simplified Architecture** - Removed Prometheus/Grafana monitoring stack, focus on text reports  
✅ **Four Comprehensive Reports** - performance_metrics.txt, dpi_packets_detailed.txt, dpi_flows_detailed.txt, mqtt_packets_detailed.txt  
✅ **Clean Documentation** - Removed redundant docs, kept only essentials  

## License

See [LICENSE](LICENSE) file.

---

**Note**: This project is designed for research and educational purposes in industrial network security.
