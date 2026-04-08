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
