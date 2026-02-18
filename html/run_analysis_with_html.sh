#!/bin/bash
#
# IWSN Security - Analyze PCAP with HTML Dashboard
# Lightweight alternative - no Docker required!
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DPI_ENGINE="$PROJECT_ROOT/c_dpi_engine"
GRAFANA_DIR="$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if PCAP file is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <pcap_file>"
    echo "Example: $0 ../scripts/attack_samples/syn_flood.pcap"
    exit 1
fi

PCAP_FILE="$1"

# Check if PCAP file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file not found: $PCAP_FILE"
    exit 1
fi

print_info "PCAP file: $PCAP_FILE"
echo ""

# Check if DPI engine exists
if [ ! -f "$DPI_ENGINE/bin/dpi_mqtt_analyzer" ]; then
    echo "Error: DPI engine not found. Please compile it first:"
    echo "  cd c_dpi_engine && make"
    exit 1
fi

# Run the analysis
print_info "Running DPI/IDS/MQTT analysis..."
echo "================================================================================"
cd "$DPI_ENGINE"
./bin/dpi_mqtt_analyzer "$PCAP_FILE"
ANALYSIS_EXIT_CODE=$?

if [ $ANALYSIS_EXIT_CODE -ne 0 ]; then
    echo "Error: Analysis failed with exit code $ANALYSIS_EXIT_CODE"
    exit $ANALYSIS_EXIT_CODE
fi

echo "================================================================================"
print_success "Analysis completed successfully"
echo ""

# Generate HTML dashboard
print_info "Generating HTML dashboard..."
cd "$GRAFANA_DIR"
python3 generate_html_dashboard.py "$DPI_ENGINE"
DASHBOARD_EXIT_CODE=$?

if [ $DASHBOARD_EXIT_CODE -eq 0 ]; then
    print_success "Dashboard generated successfully!"
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║              📊 HTML DASHBOARD READY                           ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║  Dashboard: c_dpi_engine/analysis_report.html                  ║"
    echo "║  (Should open automatically in browser)                        ║"
    echo "║                                                                ║"
    echo "║  To manually open:                                             ║"
    echo "║    xdg-open c_dpi_engine/analysis_report.html                  ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
else
    echo "Error: Failed to generate dashboard"
    exit $DASHBOARD_EXIT_CODE
fi
