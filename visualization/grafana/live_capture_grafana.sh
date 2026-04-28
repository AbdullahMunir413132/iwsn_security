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
WORKSPACE_ROOT="$(cd "$PROJECT_ROOT/.." && pwd)"
VENV_PYTHON="$WORKSPACE_ROOT/.venv/bin/python3"
PYTHON_BIN="python3"
MQTT_BRIDGE="$PROJECT_ROOT/scripts/mqtt_sensor_bridge.py"

if [ -x "$VENV_PYTHON" ]; then
    PYTHON_BIN="$VENV_PYTHON"
fi

# Preserve the original user's HOME for pip packages installed as user
if [ -n "$SUDO_USER" ]; then
    REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    export PYTHONPATH="${REAL_HOME}/.local/lib/python3/dist-packages:${REAL_HOME}/.local/lib/python3.12/dist-packages:${REAL_HOME}/.local/lib/python3.11/dist-packages:${PYTHONPATH:-}"
    export PATH="${REAL_HOME}/.local/bin:${PATH}"
fi

# ── Process-group cleanup ──────────────────────────────────────────────
# Declared early so the trap fires even if a later command exits prematurely.
WATCH_PID=""
BRIDGE_PID=""

_cleanup() {
    if [ -n "$WATCH_PID" ]; then
        kill "$WATCH_PID"  2>/dev/null || true
        wait  "$WATCH_PID" 2>/dev/null || true
    fi
    if [ -n "$BRIDGE_PID" ]; then
        kill "$BRIDGE_PID"  2>/dev/null || true
        wait  "$BRIDGE_PID" 2>/dev/null || true
    fi
}
trap _cleanup EXIT INT TERM

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
if "$PYTHON_BIN" -c "import influxdb_client" 2>/dev/null; then
    PYTHON_OK=1
else
    print_warn "influxdb-client not found for selected Python. Installing..."
    "$PYTHON_BIN" -m pip install influxdb-client 2>/dev/null
    "$PYTHON_BIN" -c "import influxdb_client" 2>/dev/null && PYTHON_OK=1
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
# ── Remove stale end-of-session report files before live capture ───────────────
# These files are written only when a session ENDS.  If left from a previous
# run, push_metrics.py would read old data and send it to Grafana instead of
# the fresh live-snapshot values — causing threat panels to appear frozen.
print_info "Clearing stale report files from previous session..."
rm -f "$DPI_ENGINE/ids_detailed_report.txt" \
       "$DPI_ENGINE/performance_metrics.txt" \
       "$DPI_ENGINE/dpi_detailed_report.txt" \
       "$DPI_ENGINE/mqtt_packets_detailed.txt"
print_success "Stale reports cleared"
# ── Start real-time Grafana metrics watcher ──────────────────────
WATCH_PID=""
if [ "$GRAFANA_AVAILABLE" -eq 1 ]; then
    print_info "Starting real-time metrics exporter (5s watch interval)..."
    "$PYTHON_BIN" "$SCRIPT_DIR/push_metrics.py" "$DPI_ENGINE" --watch --interval 5 >/tmp/iwsn_grafana_watch.log 2>&1 &
    WATCH_PID=$!
    print_success "Real-time exporter started (pid: $WATCH_PID)"
fi
# ── Start MQTT sensor bridge (auto-detect TLS) ───────────────────────────
BRIDGE_PID=""
if [ "$GRAFANA_AVAILABLE" -eq 1 ] && [ -f "$MQTT_BRIDGE" ]; then
    print_info "Starting MQTT sensor bridge (auto-detect TLS port)..."
    "$PYTHON_BIN" "$MQTT_BRIDGE" \
        --auto-detect-tls \
        >/tmp/iwsn_mqtt_bridge.log 2>&1 &
    BRIDGE_PID=$!
    print_success "MQTT sensor bridge started (pid: $BRIDGE_PID)  log: /tmp/iwsn_mqtt_bridge.log"
fi
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

# Stop background watcher if it was started
if [ -n "$WATCH_PID" ]; then
    print_info "Stopping real-time metrics exporter..."
    kill "$WATCH_PID" 2>/dev/null || true
    wait "$WATCH_PID" 2>/dev/null || true
    WATCH_PID=""  # prevent double-kill from trap
fi

# Stop MQTT sensor bridge if it was started
if [ -n "$BRIDGE_PID" ]; then
    print_info "Stopping MQTT sensor bridge..."
    kill "$BRIDGE_PID" 2>/dev/null || true
    wait "$BRIDGE_PID" 2>/dev/null || true
    BRIDGE_PID=""  # prevent double-kill from trap
fi

echo "════════════════════════════════════════════════════════════════"
echo ""

# ── Push final metrics to Grafana after capture ───────────────────
if [ "$GRAFANA_AVAILABLE" -eq 1 ] && [ -f "$DPI_ENGINE/performance_metrics.txt" ]; then
    print_info "Pushing captured metrics to Grafana..."
    "$PYTHON_BIN" "$SCRIPT_DIR/push_metrics.py" "$DPI_ENGINE"
    if [ $? -eq 0 ]; then
        print_success "Metrics pushed to Grafana"
        echo "  View results: http://localhost:3000"
    else
        print_warn "Failed to push metrics (Grafana may have stopped)"
    fi
    echo ""
fi

print_success "Live capture session ended."
