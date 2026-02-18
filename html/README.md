# IWSN Security - HTML Dashboard

Visualize your PCAP analysis results with interactive HTML dashboards!

---

## ⚡ Quick Start

### Run Analysis with HTML Dashboard

```bash
cd html
./run_analysis_with_html.sh ../scripts/attack_samples/syn_flood.pcap
```

This will:
1. Run DPI Engine analysis
2. Run Rule Engine (IDS) attack detection
3. Run MQTT Parser (if MQTT traffic present)
4. Generate detailed reports
5. Create interactive HTML dashboard
6. Automatically open in your browser

---

## 📊 Dashboard Features

The HTML dashboard includes:

- **System Overview**: Processing metrics, throughput, CPU usage
- **Performance Metrics Table**: DPI Engine, Rule Engine, MQTT Parser stats
- **DPI Engine Details**: Layer parsing rates, protocol detection accuracy
- **IDS/Attack Detection**: Detected attacks, severity distribution, top attackers
- **Interactive Charts**: Visual representation of metrics
- **Detailed Reports**: Links to full text reports

---

## 📁 Available Test Files

```bash
# Attack samples (in scripts/attack_samples/)
./run_analysis_with_html.sh ../scripts/attack_samples/syn_flood.pcap
./run_analysis_with_html.sh ../scripts/attack_samples/malware_rudy_attack.pcap
./run_analysis_with_html.sh ../scripts/attack_samples/icmp_flood.pcap
./run_analysis_with_html.sh ../scripts/attack_samples/tcp_syn_scan.pcap

# Normal traffic samples (in scripts/pcap_samples/)
./run_analysis_with_html.sh ../scripts/pcap_samples/mqtt_normal_traffic.pcap
./run_analysis_with_html.sh ../scripts/pcap_samples/all_packets_wlp3s0_full.pcap
./run_analysis_with_html.sh ../scripts/pcap_samples/dns.pcap
```

---

## 🔄 Workflow

```
┌─────────────────┐
│  PCAP File      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  DPI Engine     │
│  Analysis       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Rule Engine    │
│  (IDS)          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  MQTT Parser    │
│  (if present)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Generate       │
│  Reports        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Create HTML    │
│  Dashboard      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Open in        │
│  Browser        │
└─────────────────┘
```

---

## 📝 Manual Usage

If you want to run components separately:

```bash
# 1. Run analysis
cd c_dpi_engine
./bin/dpi_mqtt_analyzer ../scripts/attack_samples/syn_flood.pcap

# 2. Generate HTML dashboard only
cd ../html
python3 generate_html_dashboard.py ../c_dpi_engine
```

---

## 📄 Generated Files

After running analysis, you'll find these files in `c_dpi_engine/`:

- `analysis_report.html` - Interactive HTML dashboard
- `performance_metrics.txt` - Detailed performance metrics
- `dpi_detailed_report.txt` - DPI flows and packet details
- `ids_detailed_report.txt` - Attack detection details
- `mqtt_packets_detailed.txt` - MQTT message details (if applicable)

---

## 🛠️ Troubleshooting

### Dashboard doesn't open automatically
```bash
# Manually open the dashboard
xdg-open ../c_dpi_engine/analysis_report.html
# Or
firefox ../c_dpi_engine/analysis_report.html
```

### Python script error
```bash
# Check if reports exist
ls -l ../c_dpi_engine/*.txt

# Run with verbose output
python3 -v generate_html_dashboard.py ../c_dpi_engine
```

---

## 📊 Understanding the Metrics

### DPI Engine Accuracy
- **Layer Parsing**: % of packets successfully parsed at each layer (L2-L5)
- **Protocol Detection**: % of packets with identified protocols (vs unknown)
- **Overall**: Average of all parsing layers + protocol detection

### Rule Engine Accuracy
- **Confidence-Based**: Average confidence of all detected attacks
- **100% = High confidence detections**
- **<100% = Mixed or lower confidence detections**

### Performance Metrics
- **Packets/sec**: Processing throughput
- **Time per Packet**: Average processing time (microseconds)
- **Memory Usage**: Total memory consumed by analysis

---

## 🎯 Next Steps

1. Try analyzing different PCAP files
2. Review detailed reports for insights
3. Check accuracy metrics to validate detection quality
4. Explore attack detection details in IDS report

For more information, see [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
