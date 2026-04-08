# IWSN Security - HTML Dashboard Quick Reference

**Created:** February 11, 2026  
**Updated:** February 12, 2026

---

## ⚡ Quick Start

### One-Line Command:
```bash
cd html && ./run_analysis_with_html.sh ../scripts/attack_samples/syn_flood.pcap
```

### What you get:
- ✅ Beautiful interactive HTML report
- ✅ Opens automatically in browser  
- ✅ Attack notifications
- ✅ Performance charts
- ✅ Detailed metrics tables
- ✅ No installation needed

### Output file:
```
c_dpi_engine/analysis_report.html
```

---

## 📋 Common Commands

### Analyze Different PCAP Files

```bash
# Attack samples
cd html
./run_analysis_with_html.sh ../scripts/attack_samples/syn_flood.pcap
./run_analysis_with_html.sh ../scripts/attack_samples/malware_rudy_attack.pcap
./run_analysis_with_html.sh ../scripts/attack_samples/icmp_flood.pcap
./run_analysis_with_html.sh ../scripts/attack_samples/tcp_syn_scan.pcap

# Normal traffic
./run_analysis_with_html.sh ../scripts/pcap_samples/mqtt_normal_traffic.pcap
./run_analysis_with_html.sh ../scripts/pcap_samples/all_packets_wlp3s0_full.pcap
./run_analysis_with_html.sh ../scripts/pcap_samples/dns.pcap
```

### Manual Mode (Advanced)

```bash
# 1. Run analysis manually
cd c_dpi_engine
./bin/dpi_mqtt_analyzer ../scripts/attack_samples/syn_flood.pcap

# 2. Generate HTML dashboard
cd ../html
python3 generate_html_dashboard.py ../c_dpi_engine

# 3. Open in browser
xdg-open ../c_dpi_engine/analysis_report.html
```
cd grafana

# Start
docker-compose up -d

# Stop
docker-compose down

# View logs
docker-compose logs -f

# Reset everything
docker-compose down -v && docker-compose up -d
```

### Manual Steps (If Needed)

```bash
# 1. Run analysis
cd c_dpi_engine
./bin/dpi_mqtt_analyzer ../scripts/attack_samples/syn_flood.pcap

# 2a. Generate HTML
cd ../grafana
python3 generate_html_dashboard.py ../c_dpi_engine

# 2b. OR push to Grafana
python3 push_metrics.py ../c_dpi_engine
```

---

## 🎨 Dashboard Features

### HTML Dashboard Shows:
- 🚨 Attack count (turns red if attacks detected)
- 📦 Total packets processed
- ⚡ Throughput (packets/sec)

---

## 📊 Dashboard Features

### HTML Dashboard Shows:
- 📈 System overview with key metrics
- 🔢 Performance metrics table (DPI, IDS, MQTT)
- 🎯 DPI Engine accuracy breakdown
- ⚠️ Attack detection details
- 🚫 Blocked IPs list
- ⏱️ Processing time breakdown
- 🔍 Protocol detection rate  
- 📊 Attack type distribution
- 📈 Interactive charts
- 🎨 Clean, responsive design

---

## 🐛 Quick Troubleshooting

### HTML Dashboard Issues

**Problem:** Browser doesn't open automatically
```bash
xdg-open ../c_dpi_engine/analysis_report.html
# Or
firefox ../c_dpi_engine/analysis_report.html
```

**Problem:** No data displayed in dashboard
```bash
# Make sure reports exist
ls -lh ../c_dpi_engine/*.txt

# Check if reports have content
cat ../c_dpi_engine/performance_metrics.txt | head -20
```

**Problem:** Python script fails
```bash
# Check Python version
python3 --version

# Run script manually with verbose output
cd html
python3 -v generate_html_dashboard.py ../c_dpi_engine
```

---

## 📊 Sample Output

### When Attacks Detected:
```
╔════════════════════════════════════════════════════════════════╗
║  ⚠️  ALERT: 30 attack(s) detected! 5 IP(s) blocked.           ║
╠════════════════════════════════════════════════════════════════╣
║  Attack Types:                                                 ║
║    • HTTP Flood: 25                                            ║
║    • RUDY Attack: 4                                            ║
║    • Port Scan: 1                                              ║
║                                                                ║
║  Blocked IPs:                                                  ║
║    • 147.32.84.165                                             ║
║    • 79.174.72.172                                             ║
║    • 78.159.114.121                                            ║
║    • 147.32.84.207                                             ║
║    • 147.32.84.229                                             ║
╚════════════════════════════════════════════════════════════════╝
```

### When Traffic is Clean:
```
╔════════════════════════════════════════════════════════════════╗
║  ✅ SECURE: No attacks detected in this capture.              ║
╠════════════════════════════════════════════════════════════════╣
║  Performance:                                                  ║
║    • Packets: 145                                              ║
║    • Throughput: 38 pps                                        ║
║    • Processing: 3.82 ms                                       ║
║    • DPI Accuracy: 100.0%                                      ║
║    • IDS Accuracy: 100.0%                                      ║
╚════════════════════════════════════════════════════════════════╝
```

---

## 📁 Generated Files

After analysis, check these files in `c_dpi_engine/`:

```bash
ls -lh ../c_dpi_engine/
# Should show:
- analysis_report.html          # Interactive HTML dashboard
- performance_metrics.txt       # Detailed metrics
- dpi_detailed_report.txt       # Flow-by-flow analysis
- ids_detailed_report.txt       # Attack detection details
- mqtt_packets_detailed.txt     # MQTT message details
```

---

## 🔗 Related Documentation

- **Main README:** [README.md](README.md)
- **Installation Guide:** [../docs/INSTALLATION_GUIDE.md](../docs/INSTALLATION_GUIDE.md)
- **Attack Reference:** [../docs/ATTACK_DETECTION_REFERENCE.md](../docs/ATTACK_DETECTION_REFERENCE.md)
- **Technical Architecture:** [../docs/TECHNICAL_ARCHITECTURE_GUIDE.md](../docs/TECHNICAL_ARCHITECTURE_GUIDE.md)

---

## 💡 Pro Tips

1. **Save HTML reports** - They work offline, great for archiving
2. **Compare PCAPs** - Run analysis on multiple files and compare
3. **Check accuracy** - Low accuracy (<80%) may indicate issues
4. **Review detailed reports** - Click links in dashboard for full details
5. **Test with samples** - Use provided attack samples to validate setup

---

**Need more help?** See the full [.md](README.md) for complete documentation.

