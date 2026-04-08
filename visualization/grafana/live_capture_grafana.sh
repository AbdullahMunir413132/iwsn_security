#!/bin/bash
#
# IWSN Security - Live Capture with Grafana Real-Time Monitoring
# Starts live packet capture and continuously pushes metrics to Grafana.
#
# Usage:
#   sudo ./live_capture_grafana.sh
#
# This will:
#   1. Start the DPI engine in live capture mode (foreground/interactive)
#   2. After capture ends, push final metrics to Grafana
#   3. Optionally start the metrics watcher for continuous push
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DPI_ENGINE="$PROJECT_ROOT/c_dpi_engine"

# Preserve the original user's HOME for pip packages installed as user
if [ -n "$SUDO_USER" ]; then
    REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    export PYTHONPATH="${REAL_HOME}/.local/lib/python3/dist-packages:${REAL_HOME}/.local/lib/python3.12/dist-packages:${REAL_HOME}/.local/lib/python3.11/dist-packages:${PYTHONPATH:-}"
    export PATH="${REAL_HOME}/.local/bin:${PATH}"
fi

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
print_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   IWSN Security - Live Capture + Grafana Real-Time Monitor  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Check root ────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    print_error "Live capture requires root privileges."
    echo "  Run: sudo $0"
    exit 1
fi

# ── Check DPI engine ─────────────────────────────────────────────
if [ ! -f "$DPI_ENGINE/bin/dpi_mqtt_analyzer" ]; then
    print_error "DPI engine not found. Build it first:"
    echo "  cd c_dpi_engine && make clean && make"
    exit 1
fi

# ── Check Python influxdb-client ─────────────────────────────────
PYTHON_OK=0
if python3 -c "import influxdb_client" 2>/dev/null; then
    PYTHON_OK=1
else
    print_warn "influxdb-client not found for root. Installing..."
    pip3 install --break-system-packages influxdb-client 2>/dev/null \
        || python3 -m pip install --break-system-packages influxdb-client 2>/dev/null \
        || pip3 install influxdb-client 2>/dev/null
    python3 -c "import influxdb_client" 2>/dev/null && PYTHON_OK=1
    if [ $PYTHON_OK -eq 1 ]; then
        print_success "influxdb-client installed"
    else
        print_warn "Could not install influxdb-client. Grafana push will be skipped."
    fi
fi

# ── Check Grafana stack ──────────────────────────────────────────
GRAFANA_AVAILABLE=0
INFLUX_OK=0
if command -v curl &> /dev/null; then
    curl -s http://localhost:8086/health 2>/dev/null | grep -q '"status":"pass"' && INFLUX_OK=1
elif command -v wget &> /dev/null; then
    wget -qO- http://localhost:8086/health 2>/dev/null | grep -q '"status":"pass"' && INFLUX_OK=1
else
    docker exec iwsn_influxdb influx ping &> /dev/null && INFLUX_OK=1
fi

if [ $INFLUX_OK -eq 1 ] && [ $PYTHON_OK -eq 1 ]; then
    GRAFANA_AVAILABLE=1
    print_success "Grafana stack is running"
    echo "  Grafana Dashboard: http://localhost:3000"
    echo "  Login: admin / iwsn_security"
elif [ $INFLUX_OK -eq 0 ]; then
    print_warn "InfluxDB not running. Start Grafana stack first (in another terminal):"
    echo "  cd visualization/grafana && ./setup_grafana.sh"
    echo ""
    read -p "  Continue with live capture only (no Grafana)? [y/N]: " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

echo ""

# ── Start live capture (foreground — interactive menu) ────────────
print_info "Starting DPI engine in live capture mode..."
echo ""
echo "  Select capture mode and network interface in the menu below."
echo "  Press Ctrl+C to stop capture at any time."
echo ""
echo "════════════════════════════════════════════════════════════════"

cd "$DPI_ENGINE"
./bin/dpi_mqtt_analyzer
DPI_EXIT=$?

echo "════════════════════════════════════════════════════════════════"
echo ""

# ── Push final metrics to Grafana after capture ───────────────────
if [ "$GRAFANA_AVAILABLE" -eq 1 ] && [ -f "$DPI_ENGINE/performance_metrics.txt" ]; then
    print_info "Pushing captured metrics to Grafana..."
    python3 "$SCRIPT_DIR/push_metrics.py" "$DPI_ENGINE" 2>/dev/null
    if [ $? -eq 0 ]; then
        print_success "Metrics pushed to Grafana"
        echo "  View results: http://localhost:3000"
    else
        print_warn "Failed to push metrics (Grafana may have stopped)"
    fi
    echo ""
fi

print_success "Live capture session ended."
