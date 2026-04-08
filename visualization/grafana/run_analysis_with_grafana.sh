#!/bin/bash
#
# IWSN Security - Run Analysis with Grafana Real-Time Push
# Runs DPI analysis on a PCAP file, then pushes metrics to Grafana.
#
# Usage:
#   ./run_analysis_with_grafana.sh <pcap_file>
#   ./run_analysis_with_grafana.sh ../scripts/attack_samples/syn_flood.pcap
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DPI_ENGINE="$PROJECT_ROOT/c_dpi_engine"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

if [ $# -eq 0 ]; then
    echo "Usage: $0 <pcap_file>"
    echo ""
    echo "Examples:"
    echo "  $0 ../../scripts/attack_samples/syn_flood.pcap"
    echo "  $0 ../../scripts/pcap_samples/mqtt_normal_traffic.pcap"
    exit 1
fi

PCAP_FILE="$1"

if [ ! -f "$PCAP_FILE" ]; then
    print_error "PCAP file not found: $PCAP_FILE"
    exit 1
fi

if [ ! -f "$DPI_ENGINE/bin/dpi_mqtt_analyzer" ]; then
    print_error "DPI engine not found. Build it first:"
    echo "  cd c_dpi_engine && make clean && make"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     IWSN Security - Analysis + Grafana Real-Time Push      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Run DPI analysis ─────────────────────────────────────
print_info "Running DPI/IDS/MQTT analysis on: $PCAP_FILE"
echo "════════════════════════════════════════════════════════════════"
cd "$DPI_ENGINE"
./bin/dpi_mqtt_analyzer "$PCAP_FILE"
ANALYSIS_EXIT=$?

if [ $ANALYSIS_EXIT -ne 0 ]; then
    print_error "Analysis failed (exit code: $ANALYSIS_EXIT)"
    exit $ANALYSIS_EXIT
fi
echo "════════════════════════════════════════════════════════════════"
print_success "Analysis completed"
echo ""

# ── Step 2: Push metrics to Grafana ──────────────────────────────
print_info "Pushing metrics to Grafana via InfluxDB..."

# Check if InfluxDB is running
# Check InfluxDB health via curl, wget, or docker exec
INFLUX_OK=0
if command -v curl &> /dev/null; then
    curl -s http://localhost:8086/health 2>/dev/null | grep -q '"status":"pass"' && INFLUX_OK=1
elif command -v wget &> /dev/null; then
    wget -qO- http://localhost:8086/health 2>/dev/null | grep -q '"status":"pass"' && INFLUX_OK=1
else
    docker exec iwsn_influxdb influx ping &> /dev/null && INFLUX_OK=1
fi
if [ $INFLUX_OK -eq 0 ]; then
    print_error "InfluxDB not running. Start Grafana stack first:"
    echo "  cd visualization/grafana && ./setup_grafana.sh"
    echo ""
    echo "  (Analysis completed successfully - reports are available in c_dpi_engine/)"
    exit 0
fi

cd "$SCRIPT_DIR"
python3 push_metrics.py "$DPI_ENGINE"
PUSH_EXIT=$?

if [ $PUSH_EXIT -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Analysis + Grafana Push Complete!              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Grafana Dashboard: http://localhost:3000                   ║"
    echo "║  Login: admin / iwsn_security                              ║"
    echo "║                                                            ║"
    echo "║  Reports also available in c_dpi_engine/:                  ║"
    echo "║    - performance_metrics.txt                               ║"
    echo "║    - ids_detailed_report.txt                               ║"
    echo "║    - mqtt_packets_detailed.txt                             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
else
    print_error "Failed to push metrics to Grafana."
    echo "  Reports are still available in c_dpi_engine/"
fi
