# Quick Start

## 1) Build analyzers

```bash
./bin/iwsn build
```

## 2) Analyze one PCAP

```bash
./bin/iwsn analyze scripts/attack_samples/syn_flood.pcap
```

## 3) Analyze + generate HTML dashboard

```bash
./bin/iwsn html scripts/attack_samples/syn_flood.pcap
```

## 4) Live MQTT capture pipeline

```bash
./bin/iwsn live
```

`live` now prompts for runtime mode selection:
- `OVS-only` (existing Grafana/OVS workflow unchanged)
- `OVS + SDN bridge` (pushes live DPI/IDS/MQTT stats to the SDN controller in parallel)

For same-device testing, use defaults:
- Controller URL: `ws://127.0.0.1:8765`
- Node IP: `127.0.0.1`

For multi-node deployments, provide unique node IDs/IPs for each node instance.

## 5) Clean generated artifacts

```bash
./bin/iwsn clean
```

## Common Input Samples

- scripts/attack_samples/syn_flood.pcap
- scripts/attack_samples/icmp_flood.pcap
- scripts/attack_samples/tcp_syn_scan.pcap
- scripts/pcap_samples/mqtt_normal_traffic.pcap

## Expected Generated Outputs

- c_dpi_engine/performance_metrics.txt
- c_dpi_engine/dpi_detailed_report.txt
- c_dpi_engine/ids_detailed_report.txt
- c_dpi_engine/mqtt_packets_detailed.txt
- visualization/reports/analysis_report.html
