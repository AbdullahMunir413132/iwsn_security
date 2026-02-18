#!/bin/bash
#
# IWSN Security - Sample PCAP Downloader
# Downloads legitimate network traffic samples for testing
#

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║         IWSN Security - Sample PCAP Downloader                 ║"
echo "║          Downloads legitimate traffic samples                  ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Create output directory
PCAP_DIR="./pcap_samples"
mkdir -p "$PCAP_DIR"

echo "[*] Output directory: $PCAP_DIR"
echo ""

# Check if wget or curl is available
if command -v wget &> /dev/null; then
    DOWNLOAD_CMD="wget -q --show-progress -O"
elif command -v curl &> /dev/null; then
    DOWNLOAD_CMD="curl -L -o"
else
    echo "[!] Neither wget nor curl found. Please install one."
    exit 1
fi

echo "════════════════════════════════════════════════════════════════"
echo "Downloading Sample PCAP Files"
echo "════════════════════════════════════════════════════════════════"
echo ""

# ========== MQTT Samples ==========
echo "[1/10] Downloading MQTT sample..."
$DOWNLOAD_CMD "$PCAP_DIR/mqtt.pcap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mqtt.pcap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] mqtt.pcap"
else
    echo "    [!] Failed to download mqtt.pcap"
fi

# ========== HTTP Samples ==========
echo "[2/10] Downloading HTTP sample..."
$DOWNLOAD_CMD "$PCAP_DIR/http.cap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] http.cap"
else
    echo "    [!] Failed to download http.cap"
fi

# ========== DNS Samples ==========
echo "[3/10] Downloading DNS sample..."
$DOWNLOAD_CMD "$PCAP_DIR/dns.cap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] dns.cap"
else
    echo "    [!] Failed to download dns.cap"
fi

# ========== DHCP Samples ==========
echo "[4/10] Downloading DHCP sample..."
$DOWNLOAD_CMD "$PCAP_DIR/dhcp.pcap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dhcp.pcap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] dhcp.pcap"
else
    echo "    [!] Failed to download dhcp.pcap"
fi

# ========== FTP Samples ==========
echo "[5/10] Downloading FTP sample..."
$DOWNLOAD_CMD "$PCAP_DIR/ftp.pcap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ftp.pcap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] ftp.pcap"
else
    echo "    [!] Failed to download ftp.pcap"
fi

# ========== Telnet Samples ==========
echo "[6/10] Downloading Telnet sample..."
$DOWNLOAD_CMD "$PCAP_DIR/telnet.pcap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/telnet-raw.pcap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] telnet.pcap"
else
    echo "    [!] Failed to download telnet.pcap"
fi

# ========== ICMP Samples ==========
echo "[7/10] Downloading ICMP/Ping sample..."
$DOWNLOAD_CMD "$PCAP_DIR/icmp.pcap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/icmp.cap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] icmp.pcap"
else
    echo "    [!] Failed to download icmp.pcap"
fi

# ========== TCP Handshake Samples ==========
echo "[8/10] Downloading TCP handshake sample..."
$DOWNLOAD_CMD "$PCAP_DIR/tcp_handshake.pcap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/tcp-ecn-sample.pcap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] tcp_handshake.pcap"
else
    echo "    [!] Failed to download tcp_handshake.pcap"
fi

# ========== ARP Samples ==========
echo "[9/10] Downloading ARP sample..."
$DOWNLOAD_CMD "$PCAP_DIR/arp.pcap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/arp-storm.pcap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] arp.pcap"
else
    echo "    [!] Failed to download arp.pcap"
fi

# ========== Mixed Normal Traffic ==========
echo "[10/10] Downloading mixed normal traffic..."
$DOWNLOAD_CMD "$PCAP_DIR/mixed_normal.pcap" \
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http_espn.pcap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] mixed_normal.pcap"
else
    echo "    [!] Failed to download mixed_normal.pcap"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Download Complete!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Downloaded files:"
ls -lh "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.cap 2>/dev/null | awk '{print "  " $9 " - " $5}'
echo ""
echo "File count:"
PCAP_COUNT=$(ls -1 "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.cap 2>/dev/null | wc -l)
echo "  Total: $PCAP_COUNT PCAP files"
echo ""
echo "To analyze with DPI engine:"
echo "  ./bin/dpi_engine $PCAP_DIR/mqtt.pcap"
echo ""
echo "To analyze with IDS:"
echo "  ./bin/dpi_engine_ids $PCAP_DIR/http.cap"
echo ""
