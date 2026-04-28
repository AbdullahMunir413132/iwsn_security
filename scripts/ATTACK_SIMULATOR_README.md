# IWSN Attack Simulator — `attack_simulator.py`

RFC-compliant network attack traffic generator for the IWSN Security pipeline. Produces synthetic PCAP files or transmits packets live over the wire. Covers all 21 attack types detected by the C DPI engine plus realistic MQTT sensor traffic.

---

## Requirements

| Dependency | Notes |
|------------|-------|
| Python 3.10+ | Must be the project venv: `/home/saad-kashif/test/.venv/bin/python3` |
| Scapy | Installed in project venv |
| Root / `sudo` | Required for live transmission only |
| Linux | `sendp()` live mode uses raw sockets |

---

## Modes

### PCAP Mode (default)
Generates `.pcap` files in an output directory along with a `manifest.json` ground truth file. No root required.

```bash
# All 21 attacks + MQTT + normal traffic
python3 attack_simulator.py --preset all

# Single attack
python3 attack_simulator.py --preset syn_flood

# MQTT sensor traffic only
python3 attack_simulator.py --preset mqtt_traffic

# Custom output directory
python3 attack_simulator.py --preset all --output ./my_pcaps

# Set difficulty
python3 attack_simulator.py --preset all --difficulty medium

# Reproducible output
python3 attack_simulator.py --preset all --seed 42
```

### Live Transmission Mode (`--live`)
Sends packets directly onto the wire via Scapy `sendp()`. Requires root.

```bash
# Single attack live
sudo python3 attack_simulator.py --preset syn_flood --live --iface br0 --target 192.168.1.100

# All attacks live, 300 packets per attack max
sudo python3 attack_simulator.py --preset all --live --iface br0 --target 192.168.1.100 --max-pkts 300

# MQTT traffic live
sudo python3 attack_simulator.py --preset mqtt_traffic --live --iface br0

# Throttled send (10 ms inter-packet gap)
sudo python3 attack_simulator.py --preset udp_flood --live --iface br0 --inter 10
```

> **Wireless / OVS deployment**: use the `br0` OVS bridge interface on a node device, not the dev laptop's wireless NIC. See [PHYSICAL_DEPLOYMENT_GUIDE.md](../PHYSICAL_DEPLOYMENT_GUIDE.md).

#### Live mode flags

| Flag | Default | Description |
|------|---------|-------------|
| `--iface` | Scapy default | Network interface name |
| `--target` | `192.168.1.100` | Destination IP override |
| `--inter MS` | auto | Inter-packet gap in milliseconds. Omit for floods (gap=0). Timed attacks (slowloris, RUDY, scans) honour their scheduled timestamps automatically when omitted. |
| `--max-pkts N` | 500 | Per-attack packet cap. Use `0` for no cap. Applied before noise injection. |

#### Venv under sudo
When running `sudo python3`, the venv is dropped. The script auto-detects and re-injects the venv's `site-packages`. If that fails, use one of:

```bash
# Preferred — preserve venv
sudo /home/saad-kashif/test/.venv/bin/python3 scripts/attack_simulator.py --live ...

# Alternative — preserve environment
sudo -E env PATH="$PATH" python3 attack_simulator.py --live ...
```

---

## Difficulty Levels

| Level | Rate multiplier | Noise | Description |
|-------|----------------|-------|-------------|
| `easy` | ×2.0 | 0% | Textbook attacks, obvious signatures |
| `medium` | ×1.0 | 20% | Standard rates with some normal traffic |
| `hard` | ×0.5 | 50% | Low-and-slow with heavy noise mixing |
| `extreme` | ×0.3 | 70% | Evasive, multi-vector, heavily camouflaged |

Default is `easy`. Noise packets are real MQTT/HTTP/DNS/ICMP traffic interleaved randomly.

---

## Attack Presets

List all presets at any time:

```bash
python3 attack_simulator.py --list
```

| Preset | Attack Type | RFC / Reference |
|--------|-------------|-----------------|
| `syn_flood` | SYN Flood | RFC 4987, RFC 793 |
| `udp_flood` | UDP Flood | RFC 768, RFC 4732 |
| `icmp_flood` | ICMP Flood | RFC 792, RFC 4732 |
| `http_flood` | HTTP Flood | RFC 9110, RFC 4732 |
| `ping_of_death` | Ping of Death | RFC 791 §3.2, RFC 6274 |
| `land_attack` | Land Attack | RFC 6274, CVE-1999-0016 |
| `smurf_attack` | Smurf Attack | RFC 2827 (BCP 38) |
| `fraggle_attack` | Fraggle Attack | RFC 768, RFC 6274 |
| `teardrop_attack` | Teardrop Attack | RFC 791 §3.2, RFC 6274 |
| `tcp_syn_scan` | TCP SYN Scan | RFC 793 §3.9 |
| `tcp_connect_scan` | TCP Connect Scan | RFC 793 |
| `udp_scan` | UDP Scan | RFC 768 |
| `xmas_scan` | Xmas Tree Scan | RFC 793 §3.9 |
| `null_scan` | NULL Scan | RFC 793 §3.9 |
| `fin_scan` | FIN Scan | RFC 793 §3.9 |
| `rudy_attack` | RUDY (Slow POST) | RFC 9110, OWASP |
| `slowloris` | Slowloris | RFC 9110, OWASP |
| `dns_amplification` | DNS Amplification | RFC 5358, RFC 5625 |
| `ntp_amplification` | NTP Amplification | RFC 5905, CVE-2013-5211 |
| `arp_spoofing` | ARP Spoofing | RFC 826, RFC 5227 |
| `ip_spoofing` | IP Spoofing | RFC 2827 (BCP 38) |
| `mqtt_traffic` | MQTT Sensor Traffic | MQTT v3.1.1 (OASIS) |
| `normal_traffic` | Clean IWSN Traffic | N/A |

---

## Detection Thresholds

Each generator is tuned to satisfy the C DPI engine's detection thresholds:

| Attack | Key threshold(s) |
|--------|-----------------|
| SYN Flood | >20 SYN/s, half-open ≥5 (per-flow) **or** >100 unique sources (aggregate) |
| UDP Flood | >50 pps, ≥100 packets, unique dst ports >5 (per-flow) **or** >100 sources (aggregate) |
| ICMP Flood | >15 pps, ≥10 packets (per-flow) **or** >100 sources (aggregate) |
| HTTP Flood | >30 req/s, ≥5 packets to port 80/8080 (per-flow) **or** >100 sources (aggregate) |
| Ping of Death | IP total-length = 65535 (RFC 791 maximum) |
| Land Attack | src IP == dst IP **and** src port == dst port — fires on first packet |
| Smurf / Fraggle | Broadcast dst MAC, broadcast dst IP, ICMP/UDP echo-chargen, >10–15 pps |
| Teardrop | IP ihl=1, total-length=4 → frame <20 bytes, overlapping fragment offsets |
| Port Scans | ≥10 unique dst ports from same src→dst (aggregate scan detector) |
| RUDY | <10 B/s avg rate, duration >30s, established connections >0 |
| Slowloris | <5 B/s avg rate, <2 pps, duration >30s, ≥5 established connections |
| DNS Amplification | Avg response >512 B, >5 pps, src port 53 |
| NTP Amplification | Avg response >468 B, >5 pps, src port 123 |
| ARP Spoofing | ≥6 distinct MACs for the same source IP |
| IP Spoofing | Source in forbidden range (loopback, multicast, TEST-NET, reserved) — fires on first packet |

---

## Output Files (PCAP Mode)

All files are written to `--output` (default: `./simulator_output/`).

```
simulator_output/
├── syn_flood.pcap
├── udp_flood.pcap
├── ...
├── normal_traffic.pcap
└── manifest.json          ← ground truth for each PCAP
```

### `manifest.json` schema

```json
{
  "generator": "IWSN Attack Simulator v3.0",
  "timestamp": "2026-04-28 06:00:00",
  "difficulty": "easy",
  "noise_percentage": 0,
  "attacks": [
    {
      "name": "syn_flood",
      "file": "./simulator_output/syn_flood.pcap",
      "attack_type": "SYN Flood",
      "rfc_reference": "RFC 4987, RFC 793",
      "attack_packets": 2000,
      "total_packets": 2000,
      "mqtt_packets": 0,
      "noise_packets": 0,
      "file_size_bytes": 180000,
      "expected_detection": true
    }
  ]
}
```

---

## MQTT Traffic

The `mqtt_traffic` preset generates realistic IWSN sensor sessions:

- CONNECT → CONNACK → SUBSCRIBE → SUBACK → PUBLISH (×N) → PINGREQ/PINGRESP → DISCONNECT  
- Topics: temperature, humidity, pressure, light, motion, battery, valve, relay, network status  
- JSON payloads with realistic sensor ranges  
- Multiple simultaneous sensor nodes (default: 5 sessions × 20 messages)

Normal traffic mixed into attack PCAPs (at `medium`/`hard`/`extreme` difficulty) also includes MQTT PUBLISH packets.

---

## Integration with the Live Pipeline

To feed PCAPs into the DPI engine:

```bash
# Run the engine on a generated PCAP
./c_dpi_engine/bin/dpi_mqtt_analyzer ./scripts/simulator_output/syn_flood.pcap

# Push results to InfluxDB / Grafana
python3 visualization/grafana/push_metrics.py
```

To run a full live test against the engine:

```bash
# Terminal 1 — start live capture
./bin/iwsn live

# Terminal 2 — inject attack traffic
sudo python3 scripts/attack_simulator.py --preset syn_flood --live --iface <iface> --target <target_ip>
```
