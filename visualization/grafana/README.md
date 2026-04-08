# IWSN Security - Grafana Real-Time Dashboard

Real-time network monitoring with Grafana + InfluxDB for live traffic analysis.

---

## Quick Start

### 1. Start the Grafana Stack
```bash
cd visualization/grafana
./setup_grafana.sh
```

This starts **InfluxDB** (time-series DB) and **Grafana** (dashboard) via Docker.

### 2. Run Analysis & Push Metrics
```bash
# Analyze a PCAP file and push results to Grafana
./run_analysis_with_grafana.sh ../../scripts/attack_samples/syn_flood.pcap

# Or push metrics from an existing analysis
python3 push_metrics.py ../../c_dpi_engine
```

### 3. Open Dashboard
- **URL**: http://localhost:3000
- **Login**: `admin` / `iwsn_security`

---

## Live Capture Mode (Real-Time)

For continuous real-time monitoring during live packet capture:

```bash
# Terminal 1: Start Grafana stack
cd visualization/grafana
./setup_grafana.sh

# Terminal 2: Start live capture with Grafana push
sudo ./live_capture_grafana.sh
```

Or use watch mode to auto-push metrics as reports update:
```bash
python3 push_metrics.py ../../c_dpi_engine --watch
```

---

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   DPI Engine     │     │   push_metrics.py │     │    Grafana       │
│  (C binary)      │────▶│  (Python)         │────▶│  Dashboard       │
│                  │     │                   │     │  :3000           │
│  Generates .txt  │     │  Parses reports   │     │                  │
│  report files    │     │  Pushes to InfluxDB│    │  Auto-refresh 5s │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │    InfluxDB      │
                         │  Time-series DB  │
                         │  :8086           │
                         └──────────────────┘
```

---

## Dashboard Panels

The Grafana dashboard includes:

### System Overview (Row 1)
- **Total Packets** - Packets processed count
- **Attacks Detected** - Total attack count (red if > 0)
- **Blocked IPs** - Number of blocked IP addresses
- **Throughput** - Packets per second
- **Processing Time** - Total analysis time (ms)
- **CPU Usage** - System CPU usage gauge

### Real-Time Traffic (Row 2)
- **Throughput Over Time** - Line chart of packets/sec
- **Packets Processed Over Time** - Bar chart of packet counts

### DPI Engine Performance (Row 3)
- **Layer 2/3/4/5 Parsing Rates** - Gauge panels (0-100%)

### IDS / Attack Detection (Row 4)
- **Attacks Over Time** - Stacked line chart by attack type
- **Attack Type Distribution** - Donut/pie chart

### Detection Accuracy (Row 5)
- **Precision** - Detection precision gauge
- **Recall** - Detection recall gauge
- **Overall Accuracy** - Overall accuracy gauge

### MQTT / IoT Analysis (Row 6)
- **MQTT Flows** - Count of MQTT flows detected
- **Messages Parsed** - MQTT messages parsed
- **Sensor Data Extracted** - IoT sensor data points
- **MQTT Messages Over Time** - Timeline chart
- **System Metrics Over Time** - CPU/Memory timeline

---

## File Structure

```
visualization/grafana/
├── docker-compose.yml              # Docker services (InfluxDB + Grafana)
├── push_metrics.py                 # Metrics exporter (report → InfluxDB)
├── setup_grafana.sh                # One-command setup script
├── run_analysis_with_grafana.sh    # Analyze PCAP + push to Grafana
├── live_capture_grafana.sh         # Live capture + real-time Grafana
├── README.md                       # This file
├── provisioning/
│   ├── datasources/
│   │   └── influxdb.yml            # Auto-configure InfluxDB datasource
│   └── dashboards/
│       └── dashboard_provider.yml  # Auto-load dashboard JSONs
└── dashboards/
    └── iwsn_realtime_dashboard.json  # Pre-built Grafana dashboard
```

---

## Requirements

- **Docker** and **Docker Compose**
- **Python 3** with `influxdb-client` package

### Install Dependencies
```bash
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Python InfluxDB client
pip3 install influxdb-client
```

---

## Commands Reference

| Command | Description |
|---|---|
| `./setup_grafana.sh` | Start InfluxDB + Grafana |
| `./run_analysis_with_grafana.sh <pcap>` | Analyze PCAP + push to Grafana |
| `sudo ./live_capture_grafana.sh` | Live capture with real-time Grafana |
| `python3 push_metrics.py <dir>` | Push existing reports to Grafana |
| `python3 push_metrics.py <dir> --watch` | Watch mode (auto-push on change) |
| `docker compose down` | Stop Grafana stack |
| `docker compose down -v` | Stop + delete data |
| `docker compose logs -f` | View container logs |

---

## Troubleshooting

### Grafana not accessible
```bash
# Check if containers are running
docker ps

# Restart
cd visualization/grafana
docker compose restart
```

### No data in dashboard
```bash
# Verify reports exist
ls -lh ../../c_dpi_engine/*.txt

# Re-push metrics
python3 push_metrics.py ../../c_dpi_engine
```

### InfluxDB connection error
```bash
# Check InfluxDB health
curl http://localhost:8086/health

# Check logs
docker compose logs influxdb
```

---

## Comparison: HTML vs Grafana

| Feature | HTML Dashboard | Grafana Dashboard |
|---|---|---|
| **Use Case** | PCAP analysis (offline) | Real-time monitoring |
| **Requirements** | Python 3 only | Docker + Python 3 |
| **Auto-refresh** | No (static report) | Yes (5s interval) |
| **Historical data** | No | Yes (InfluxDB storage) |
| **Live capture** | No | Yes (watch mode) |
| **Portable** | Yes (single .html file) | No (needs running stack) |
| **Setup** | Zero | `./setup_grafana.sh` |
