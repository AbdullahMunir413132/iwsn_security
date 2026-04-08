#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  IWSN Security — Live MQTT Traffic Capture & Analysis
# ══════════════════════════════════════════════════════════════
#
#  Captures real MQTT traffic from ESP32 sensors, saves as PCAP,
#  and runs it through the DPI + IDS + MQTT Analyzer.
#
#  Usage:
#    ./capture_live_mqtt.sh              # Capture for 60 seconds (default)
#    ./capture_live_mqtt.sh 120          # Capture for 120 seconds
#    ./capture_live_mqtt.sh 30 --analyze # Capture 30s + auto-analyze
#    ./capture_live_mqtt.sh --monitor    # Just monitor MQTT (no capture)
#
# ══════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CAPTURE_DIR="$SCRIPT_DIR/live_captures"
DPI_BINARY="$PROJECT_ROOT/c_dpi_engine/bin/dpi_mqtt_analyzer"
DURATION=${1:-60}
AUTO_ANALYZE=false
MONITOR_ONLY=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Parse arguments
for arg in "$@"; do
    case $arg in
        --analyze) AUTO_ANALYZE=true ;;
        --monitor) MONITOR_ONLY=true ;;
        [0-9]*) DURATION=$arg ;;
    esac
done

# ── Banner ──
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║     🛡️  IWSN Security — Live MQTT Traffic Capture           ║"
echo "║         Real Sensor Data → PCAP → DPI Analysis              ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Monitor-only mode ──
if [ "$MONITOR_ONLY" = true ]; then
    echo -e "${GREEN}📡 Subscribing to all IWSN MQTT topics...${NC}"
    echo -e "${YELLOW}   Press Ctrl+C to stop${NC}"
    echo ""
    mosquitto_sub -h localhost -t 'iwsn/#' -v | while read -r line; do
        topic=$(echo "$line" | cut -d' ' -f1)
        payload=$(echo "$line" | cut -d' ' -f2-)
        timestamp=$(date '+%H:%M:%S')
        echo -e "${CYAN}[$timestamp]${NC} ${MAGENTA}$topic${NC}"
        echo -e "         ${GREEN}$payload${NC}"
        echo ""
    done
    exit 0
fi

# ── Pre-flight checks ──
echo -e "${BOLD}[PRE-FLIGHT CHECKS]${NC}"
echo "───────────────────────────────────────────────────────────────"

# Check Mosquitto
if systemctl is-active --quiet mosquitto 2>/dev/null; then
    echo -e "  ${GREEN}✅ Mosquitto broker: RUNNING${NC}"
else
    echo -e "  ${RED}❌ Mosquitto broker: NOT RUNNING${NC}"
    echo -e "  ${YELLOW}   Starting Mosquitto...${NC}"
    sudo systemctl start mosquitto
    sleep 1
    echo -e "  ${GREEN}   ✅ Started!${NC}"
fi

# Check tcpdump
if command -v tcpdump &>/dev/null; then
    echo -e "  ${GREEN}✅ tcpdump: INSTALLED${NC}"
else
    echo -e "  ${RED}❌ tcpdump not found. Installing...${NC}"
    sudo apt-get install -y tcpdump
fi

# Check DPI binary
if [ -f "$DPI_BINARY" ]; then
    echo -e "  ${GREEN}✅ DPI Analyzer: BUILT${NC}"
else
    echo -e "  ${YELLOW}⚠️  DPI Analyzer not built. Building...${NC}"
    cd "$PROJECT_ROOT/c_dpi_engine"
    make clean && make 2>/dev/null
    cd "$SCRIPT_DIR"
    if [ -f "$DPI_BINARY" ]; then
        echo -e "  ${GREEN}   ✅ Build successful!${NC}"
    else
        echo -e "  ${RED}   ❌ Build failed. Will skip analysis.${NC}"
        AUTO_ANALYZE=false
    fi
fi

# Check for MQTT traffic (quick test)
echo -e "  ${CYAN}🔍 Checking for MQTT traffic (5 second probe)...${NC}"
MSG_COUNT=$(timeout 5 mosquitto_sub -h localhost -t 'iwsn/#' -C 1 2>/dev/null && echo "1" || echo "0")
if [ "$MSG_COUNT" = "1" ]; then
    echo -e "  ${GREEN}✅ MQTT traffic detected! ESP32 is publishing.${NC}"
else
    echo -e "  ${YELLOW}⚠️  No MQTT traffic detected yet.${NC}"
    echo -e "  ${YELLOW}   Make sure your ESP32 is powered on and connected.${NC}"
    echo -e "  ${YELLOW}   Proceeding with capture anyway...${NC}"
fi

echo ""

# ── Create capture filename ──
mkdir -p "$CAPTURE_DIR"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
PCAP_FILE="$CAPTURE_DIR/mqtt_live_${TIMESTAMP}.pcap"

echo -e "${BOLD}[CAPTURE CONFIGURATION]${NC}"
echo "───────────────────────────────────────────────────────────────"
echo -e "  Duration:    ${GREEN}${DURATION} seconds${NC}"
echo -e "  Output:      ${GREEN}${PCAP_FILE}${NC}"
echo -e "  Filter:      ${GREEN}port 1883 (MQTT)${NC}"
echo -e "  Interface:   ${GREEN}any${NC}"
echo -e "  Auto-analyze: ${GREEN}${AUTO_ANALYZE}${NC}"
echo ""

# ── Start capture ──
echo -e "${BOLD}[CAPTURING MQTT TRAFFIC]${NC}"
echo "───────────────────────────────────────────────────────────────"
echo -e "${CYAN}🔴 Recording... (${DURATION}s)${NC}"
echo -e "${YELLOW}   Capturing all port 1883 traffic on all interfaces${NC}"
echo ""

# Start tcpdump in background
sudo tcpdump -i any -w "$PCAP_FILE" port 1883 &
TCPDUMP_PID=$!

# Also show live MQTT messages in a visually appealing way
echo -e "${CYAN}📡 LIVE MQTT STREAM:${NC}"
echo "───────────────────────────────────────────────────────────────"

# Start a live subscriber in background
mosquitto_sub -h localhost -t 'iwsn/#' -v 2>/dev/null | while read -r line; do
    topic=$(echo "$line" | cut -d' ' -f1)
    payload=$(echo "$line" | cut -d' ' -f2-)
    ts=$(date '+%H:%M:%S.%N' | cut -c1-12)
    
    # Color code by topic
    case "$topic" in
        *ultrasonic*) echo -e "  ${CYAN}[$ts]${NC} 📏 ${BLUE}$topic${NC} → $payload" ;;
        *ir*) echo -e "  ${CYAN}[$ts]${NC} 🔴 ${RED}$topic${NC} → $payload" ;;
        *heartbeat*) echo -e "  ${CYAN}[$ts]${NC} 💓 ${GREEN}$topic${NC} → $payload" ;;
        *combined*) echo -e "  ${CYAN}[$ts]${NC} 📊 ${MAGENTA}$topic${NC} → $payload" ;;
        *) echo -e "  ${CYAN}[$ts]${NC} 📦 ${YELLOW}$topic${NC} → $payload" ;;
    esac
done &
SUB_PID=$!

# Wait for capture duration
sleep "$DURATION"

# ── Stop capture ──
echo ""
echo -e "${YELLOW}⏹️  Stopping capture...${NC}"
kill $SUB_PID 2>/dev/null || true
sudo kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
sleep 1

# ── Capture stats ──
if [ -f "$PCAP_FILE" ]; then
    FILE_SIZE=$(du -h "$PCAP_FILE" | cut -f1)
    PACKET_COUNT=$(tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l || echo "0")
    
    echo ""
    echo -e "${BOLD}[CAPTURE COMPLETE]${NC}"
    echo "───────────────────────────────────────────────────────────────"
    echo -e "  ${GREEN}✅ PCAP saved: ${PCAP_FILE}${NC}"
    echo -e "  ${GREEN}   File size:  ${FILE_SIZE}${NC}"
    echo -e "  ${GREEN}   Packets:    ${PACKET_COUNT}${NC}"
    echo ""
    
    # ── Auto-analyze if requested ──
    if [ "$AUTO_ANALYZE" = true ] && [ -f "$DPI_BINARY" ]; then
        echo -e "${BOLD}[DPI + MQTT ANALYSIS]${NC}"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        
        cd "$PROJECT_ROOT/c_dpi_engine"
        $DPI_BINARY "$PCAP_FILE"
        
        echo ""
        echo -e "${GREEN}✅ Analysis complete! Check the report files:${NC}"
        echo -e "   📊 performance_metrics.txt"
        echo -e "   📋 dpi_detailed_report.txt"
        echo -e "   🔒 ids_detailed_report.txt"
        echo -e "   📡 mqtt_packets_detailed.txt"
    else
        echo -e "${CYAN}💡 To analyze this capture, run:${NC}"
        echo -e "   cd $PROJECT_ROOT/c_dpi_engine"
        echo -e "   ./bin/dpi_mqtt_analyzer $PCAP_FILE"
    fi
else
    echo -e "${RED}❌ No PCAP file created. Check tcpdump permissions.${NC}"
fi

echo ""
echo "───────────────────────────────────────────────────────────────"
echo -e "${CYAN}🛡️  IWSN Security — Capture session ended.${NC}"
echo ""
