#!/usr/bin/env bash
# ============================================================================
# IWSN Security — Master Pipeline Orchestrator
# Runs the complete: Simulate → Analyze → Report → Export workflow
#
# Produces 3 consolidated reports:
#   1. Full_DPI_Report.txt   — Deep Packet Inspection (flows, protocols, packets)
#   2. Full_IWSN_Report.txt  — IDS detections + performance metrics + summary
#   3. Full_MQTT_Report.txt  — MQTT message parsing, topics, sensor payloads
#
# Usage:
#   ./run_pipeline.sh                          # Full pipeline (simulate + analyze)
#   ./run_pipeline.sh --pcap <file.pcap>       # Analyze existing PCAP only
#   ./run_pipeline.sh --live                   # Live capture mode (requires sudo)
#   ./run_pipeline.sh --simulate-only          # Generate attack PCAPs only
#   ./run_pipeline.sh --export-only            # Re-export existing reports to Grafana
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths (relative to project root)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENGINE_DIR="$PROJECT_ROOT/c_dpi_engine"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
VIZ_DIR="$PROJECT_ROOT/visualization"
REPORT_DIR="$PROJECT_ROOT/reports"
BINARY="$ENGINE_DIR/bin/iwsn_analyzer"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Colour helpers (no-op if not a terminal)
if [[ -t 1 ]]; then
    G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; NC='\033[0m'
else
    G=''; Y=''; R=''; C=''; NC=''
fi

info()  { echo -e "${C}[INFO]${NC}  $*"; }
ok()    { echo -e "${G}[  OK]${NC}  $*"; }
warn()  { echo -e "${Y}[WARN]${NC}  $*"; }
fail()  { echo -e "${R}[FAIL]${NC}  $*"; exit 1; }
banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          IWSN Security — Pipeline Orchestrator              ║"
    echo "║   DPI  ·  IDS  ·  MQTT  ·  Grafana  ·  Reports             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
MODE="full"          # full | pcap | live | simulate | export
PCAP_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pcap)
            MODE="pcap"; PCAP_FILE="$2"; shift 2 ;;
        --live)
            MODE="live"; shift ;;
        --simulate-only)
            MODE="simulate"; shift ;;
        --export-only)
            MODE="export"; shift ;;
        -h|--help)
            banner
            echo "Usage:"
            echo "  $0                          Full pipeline (simulate + analyze + export)"
            echo "  $0 --pcap <file.pcap>       Analyze an existing PCAP"
            echo "  $0 --live                   Live capture mode (needs sudo)"
            echo "  $0 --simulate-only          Generate attack PCAPs only"
            echo "  $0 --export-only            Re-export existing reports to Grafana"
            echo ""
            exit 0 ;;
        *)
            fail "Unknown option: $1  (use --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
preflight() {
    info "Pre-flight checks..."

    # Build if binary missing
    if [[ ! -x "$BINARY" ]]; then
        info "Binary not found — building..."
        make -C "$ENGINE_DIR" clean all || fail "Build failed"
    fi
    ok "Binary ready: $BINARY"

    # Python deps
    command -v python3 >/dev/null 2>&1 || fail "python3 not found"
    ok "python3 available"

    # Create report directory
    mkdir -p "$REPORT_DIR"
    ok "Report dir: $REPORT_DIR"
}

# ---------------------------------------------------------------------------
# Step 1: Attack simulation (generates PCAPs)
# ---------------------------------------------------------------------------
step_simulate() {
    info "━━━ Step 1/4: Attack Simulation ━━━"
    pushd "$SCRIPTS_DIR" > /dev/null
    python3 attack_simulator.py || fail "Attack simulator failed"
    popd > /dev/null

    local sim_dir="$SCRIPTS_DIR/simulator_output"
    local combined="$sim_dir/combined_attack_traffic.pcap"

    # Merge individual attack PCAPs into one combined file
    if command -v mergecap &>/dev/null; then
        info "Merging PCAPs with mergecap..."
        mergecap -w "$combined" "$sim_dir"/*.pcap 2>/dev/null && ok "Combined PCAP: $combined" || warn "mergecap failed — falling back"
    fi

    if [[ -f "$combined" ]]; then
        PCAP_FILE="$combined"
    else
        # Fall back to any pcap in simulator_output
        PCAP_FILE="$(find "$sim_dir" -name '*.pcap' -not -name 'combined*' -type f | head -1)"
        [[ -n "$PCAP_FILE" ]] || fail "No PCAPs generated"
        warn "Using fallback PCAP: $PCAP_FILE"
    fi
}

# ---------------------------------------------------------------------------
# Step 2: DPI + IDS + MQTT analysis
# ---------------------------------------------------------------------------
step_analyze() {
    local pcap="$1"
    info "━━━ Step 2/4: DPI + IDS + MQTT Analysis ━━━"
    info "Input: $pcap"

    pushd "$ENGINE_DIR" > /dev/null
    "$BINARY" "$pcap" || fail "Analysis engine failed"
    popd > /dev/null
    ok "Analysis complete"
}

step_analyze_live() {
    info "━━━ Step 2/4: Live Capture Mode ━━━"
    warn "Starting interactive live capture (Ctrl-C to stop)..."
    pushd "$ENGINE_DIR" > /dev/null
    sudo "$BINARY"
    popd > /dev/null
    ok "Live capture session ended"
}

# ---------------------------------------------------------------------------
# Step 3: Consolidate into 3 master reports
# ---------------------------------------------------------------------------
step_consolidate() {
    info "━━━ Step 3/4: Report Consolidation ━━━"

    local src="$ENGINE_DIR"
    local dst="$REPORT_DIR"

    # --- Full DPI Report ---
    {
        echo "================================================================================"
        echo "  FULL DPI REPORT — IWSN Security Deep Packet Inspection"
        echo "  Generated: $(date -Iseconds)"
        echo "================================================================================"
        echo ""
        if [[ -f "$src/dpi_detailed_report.txt" ]]; then
            cat "$src/dpi_detailed_report.txt"
        else
            echo "  [No DPI report available — run analysis first]"
        fi
    } > "$dst/Full_DPI_Report.txt"
    ok "Full_DPI_Report.txt"

    # --- Full IWSN Report (IDS + performance) ---
    {
        echo "================================================================================"
        echo "  FULL IWSN REPORT — Intrusion Detection & System Performance"
        echo "  Generated: $(date -Iseconds)"
        echo "================================================================================"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  SECTION 1: IDS / ATTACK DETECTION REPORT"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        if [[ -f "$src/ids_detailed_report.txt" ]]; then
            cat "$src/ids_detailed_report.txt"
        else
            echo "  [No IDS report available]"
        fi
        echo ""
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  SECTION 2: SYSTEM PERFORMANCE METRICS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        if [[ -f "$src/performance_metrics.txt" ]]; then
            cat "$src/performance_metrics.txt"
        else
            echo "  [No performance metrics available]"
        fi
    } > "$dst/Full_IWSN_Report.txt"
    ok "Full_IWSN_Report.txt"

    # --- Full MQTT Report ---
    {
        echo "================================================================================"
        echo "  FULL MQTT REPORT — Message Parsing, Topics & Sensor Payloads"
        echo "  Generated: $(date -Iseconds)"
        echo "================================================================================"
        echo ""
        if [[ -f "$src/mqtt_packets_detailed.txt" ]]; then
            cat "$src/mqtt_packets_detailed.txt"
        else
            echo "  [No MQTT report available — run analysis first]"
        fi
    } > "$dst/Full_MQTT_Report.txt"
    ok "Full_MQTT_Report.txt"

    info "All 3 consolidated reports in: $dst/"
}

# ---------------------------------------------------------------------------
# Step 4: Export metrics for Grafana/Prometheus
# ---------------------------------------------------------------------------
step_export() {
    info "━━━ Step 4/4: Grafana Metrics Export ━━━"

    if [[ -f "$VIZ_DIR/grafana_exporter.py" ]]; then
        pushd "$VIZ_DIR" > /dev/null
        python3 grafana_exporter.py --report-dir "$ENGINE_DIR" --watch 0 || warn "Grafana export had warnings"
        popd > /dev/null
        ok "Prometheus metrics exported to /tmp/iwsn_metrics.prom"
    else
        warn "grafana_exporter.py not found — skipping metrics export"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
banner
preflight

case "$MODE" in
    full)
        step_simulate
        step_analyze "$PCAP_FILE"
        step_consolidate
        step_export
        ;;
    pcap)
        [[ -f "$PCAP_FILE" ]] || fail "PCAP not found: $PCAP_FILE"
        step_analyze "$PCAP_FILE"
        step_consolidate
        step_export
        ;;
    live)
        step_analyze_live
        step_consolidate
        step_export
        ;;
    simulate)
        step_simulate
        ok "PCAPs generated in $SCRIPTS_DIR/simulator_output/"
        ;;
    export)
        step_consolidate
        step_export
        ;;
esac

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                 Pipeline Complete ✓                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Reports:                                                   ║"
echo "║    reports/Full_DPI_Report.txt    — DPI flows & protocols   ║"
echo "║    reports/Full_IWSN_Report.txt   — IDS + performance       ║"
echo "║    reports/Full_MQTT_Report.txt   — MQTT topics & payloads  ║"
echo "║                                                             ║"
echo "║  Grafana:                                                   ║"
echo "║    cd visualization/grafana && docker compose up -d         ║"
echo "║    → http://localhost:3000  (admin / iwsn_security)         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
