# IWSN Security

Deep Packet Inspection (DPI), Intrusion Detection (IDS), and MQTT protocol analysis for Industrial Wireless Sensor Networks.

## What This Repository Contains

- DPI + IDS + MQTT analyzers in C
- Attack simulation and robustness test harnesses
- Live MQTT capture tooling for real ESP32 workflows
- HTML and Grafana visualization helpers
- Technical and operational documentation

## Clean Project Structure

```text
iwsn_security/
├── bin/
│   └── iwsn                         # single project launcher
├── c_dpi_engine/                    # core C analyzers
│   ├── src/                         # C source files
│   ├── include/                     # headers
│   ├── bin/                         # generated binaries (build output)
│   ├── obj/                         # generated objects (build output)
│   └── Makefile
├── scripts/                         # simulators, runners, and live capture utilities
│   ├── attack_samples/
│   ├── pcap_samples/
│   ├── live_captures/
│   └── simulator_output/
├── visualization/
│   ├── html/                        # HTML dashboard workflow
│   ├── grafana/                     # InfluxDB + Grafana workflow
│   └── reports/                     # generated reports (kept empty in git)
├── docs/                            # project-level docs
├── module_docs/                     # module-specific deep dives
├── hardware/esp32_iwsn_sensors/     # ESP32 firmware
├── QUICKSTART.md
└── LICENSE
```

## Build

```bash
./bin/iwsn build
```

## Run Analysis

```bash
./bin/iwsn analyze scripts/attack_samples/syn_flood.pcap
```

## Run Analysis + HTML Report

```bash
./bin/iwsn html scripts/attack_samples/syn_flood.pcap
```

## Clean Generated Files

```bash
./bin/iwsn clean
```

The clean command removes build outputs, generated reports/logs, and Python cache artifacts while preserving source code and documentation.

## Main Outputs (Generated)

- `c_dpi_engine/performance_metrics.txt`
- `c_dpi_engine/dpi_detailed_report.txt`
- `c_dpi_engine/ids_detailed_report.txt`
- `c_dpi_engine/mqtt_packets_detailed.txt`
- `visualization/reports/*.html`

These are treated as runtime artifacts and should not be committed.

## Documentation

- docs/INSTALLATION_GUIDE.md
- docs/TECHNICAL_ARCHITECTURE_GUIDE.md
- docs/ATTACK_DETECTION_REFERENCE.md
- docs/PERFORMANCE_METRICS_GUIDE.md

## Requirements

- GCC toolchain
- libpcap
- nDPI
- Python 3
- Mosquitto CLI tools (for live MQTT workflows)

## License

See LICENSE.
