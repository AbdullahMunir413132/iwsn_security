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
├── visualization/         # Visualization tools
│   ├── generate_html_dashboard.py  # HTML dashboard generator
│   ├── run_analysis_with_html.sh   # HTML analysis script
│   └── grafana/           # Grafana real-time monitoring
│       ├── docker-compose.yml      # InfluxDB + Grafana stack
│       ├── push_metrics.py         # Metrics exporter to InfluxDB
│       ├── setup_grafana.sh        # One-command Grafana setup
│       ├── run_analysis_with_grafana.sh  # PCAP + Grafana push
│       ├── live_capture_grafana.sh       # Live capture + Grafana
│       ├── dashboards/                   # Pre-built dashboards
│       └── provisioning/                 # Auto-config for Grafana
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
✅ **Visualization Directory** - HTML dashboards + Grafana real-time monitoring in visualization/  

## License

See [LICENSE](LICENSE) file.

---

**Note**: This project is designed for research and educational purposes in industrial network security.
# IWSN Security

Deep Packet Inspection (DPI) + Intrusion Detection (IDS) + MQTT protocol analysis for Industrial Wireless Sensor Networks (IWSN).

The project supports:
- Offline PCAP forensics and benchmarking
- Automated robustness testing across 21 attack classes
- Live MQTT capture from real ESP32 sensor hardware
- Detailed text reports and HTML dashboards for operational visibility

---

## What This Project Delivers

- **DPI Engine (C)**: Layer 2–5 parsing with flow tracking and protocol classification
- **Rule-Based IDS**: Detects floods, scans, spoofing, amplification, and slow HTTP attacks
- **MQTT Parser**: Deep parsing of MQTT packets, topics, payloads, and session behavior
- **Performance Metrics**: Throughput, detection quality, timing breakdown, and run summaries
- **Operational Reporting**: Human-readable forensic reports and HTML visualization

---

## Build

```bash
cd c_dpi_engine
make clean && make all
```

Built binaries:
- `bin/dpi_mqtt_analyzer` → DPI + IDS + MQTT (main workflow)
- `bin/dpi_engine_ids` → DPI + IDS (no MQTT module output)
- `bin/dpi_engine` → DPI-only baseline

---

## Command Guide (What Runs What)

### 1) Generate synthetic traffic only (no analysis)

```bash
python3 scripts/attack_simulator.py --preset all --difficulty easy --output scripts/simulator_output
```

This command:
- Generates attack/normal PCAP files
- Writes `manifest.json`

This command does **not**:
- Run IDS analysis
- Generate analyzer reports

### 2) Analyze one PCAP with full pipeline (DPI → IDS → MQTT)

```bash
cd c_dpi_engine
./bin/dpi_mqtt_analyzer ../scripts/attack_samples/syn_flood.pcap
```

### 3) Single-command analysis + HTML dashboard for one PCAP

```bash
cd html
./run_analysis_with_html.sh ../scripts/attack_samples/syn_flood.pcap
```

### 4) Full automated robustness pipeline (recommended whole offline pipeline)

```bash
python3 scripts/run_robustness_test.py
```

This command orchestrates:
1. Simulator generates all PCAPs (+ normal baseline)
2. Analyzer runs each PCAP
3. Strict detection scoring and metrics generation
4. Consolidated reports in `scripts/robustness_test_output/reports/`

---

## Live ESP32 Sensor Traffic (Real Hardware)

If your ESP32 node publishes to broker topics like `iwsn/sensors/...`, use:

### Capture live MQTT traffic into PCAP

```bash
bash scripts/capture_live_mqtt.sh 120
```

- Captures `port 1883` on interface `any`
- Stores file under `scripts/live_captures/`

### Capture and auto-analyze in one command

```bash
bash scripts/capture_live_mqtt.sh 120 --analyze
```

### Live monitor only (no PCAP)

```bash
bash scripts/capture_live_mqtt.sh --monitor
```

Optional Python terminal monitor:

```bash
python3 scripts/live_mqtt_monitor.py --broker 192.168.1.20 --duration 300
```

---

## Output Artifacts

### Analyzer outputs (per run, under `c_dpi_engine/`)
- `performance_metrics.txt`
- `dpi_detailed_report.txt`
- `ids_detailed_report.txt`
- `mqtt_packets_detailed.txt`
- `analysis_report.html` (when HTML generation is used)

### Robustness outputs
- `scripts/robustness_test_output/reports/robustness_report.md`
- `scripts/robustness_test_output/reports/robustness_results.json`
- `scripts/robustness_test_output/reports/robustness_dashboard.html`

### Live capture outputs
- `scripts/live_captures/mqtt_live_*.pcap`

---

## Architecture Workflow

```text
PCAP or Live Capture
  ↓
DPI Engine (packet + flow parsing)
  ↓
Rule Engine / IDS (attack detection)
  ↓
MQTT Parser (topic/payload/session inspection)
  ↓
Metrics + Detailed Reports + Optional HTML Dashboard
```

---

## Detection Scope

The simulator/benchmark workflow includes 21 attack classes plus normal and MQTT traffic baselines, including:
- SYN/UDP/ICMP/HTTP floods
- SYN/Connect/UDP/Xmas/NULL/FIN scans
- Ping of Death, Teardrop, Smurf, Fraggle
- DNS/NTP amplification
- ARP/IP spoofing
- Slowloris and RUDY

---

## Project Achievements (Client-Facing Summary)

- Delivered an **end-to-end industrial network security platform** for packet-level visibility and threat detection.
- Integrated **deep traffic inspection with protocol intelligence** and flow-aware behavior analysis.
- Implemented **broad attack coverage** with reproducible synthetic traffic for objective validation.
- Built a **robustness testing harness** that reports precision, recall, F1, and accuracy for measurable security outcomes.
- Enabled **real hardware ingestion** from ESP32 MQTT sensor nodes for practical field validation.
- Produced **operational-grade reporting artifacts** (forensics text reports + dashboards) suitable for engineering and stakeholder review.

---

## Repository Layout

```text
iwsn_security-main/
├── c_dpi_engine/                 # C analyzers, reports, binaries
├── scripts/                      # simulator, robustness harness, live capture tools
├── hardware/esp32_iwsn_sensors/  # ESP32 firmware
├── html/                         # HTML report generation scripts
├── docs/                         # technical and operational documentation
└── module_docs/                  # module-level deep dives
```

---

## Documentation

- [docs/INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md)
- [docs/TECHNICAL_ARCHITECTURE_GUIDE.md](docs/TECHNICAL_ARCHITECTURE_GUIDE.md)
- [docs/ATTACK_DETECTION_REFERENCE.md](docs/ATTACK_DETECTION_REFERENCE.md)
- [docs/PERFORMANCE_METRICS_GUIDE.md](docs/PERFORMANCE_METRICS_GUIDE.md)

---

## Requirements

- GCC toolchain
- `libpcap`
- `nDPI`
- Python 3
- Scapy (`pip3 install scapy`)
- Mosquitto (`mosquitto`, `mosquitto_sub`, `mosquitto_pub`) for live MQTT workflows

---

## License

See [LICENSE](LICENSE).

---

> This project is intended for research, educational, and controlled test-lab security validation.
