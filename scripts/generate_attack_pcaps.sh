#!/bin/bash
#
# IWSN Security - Attack Traffic Generator
# Generates PCAP files containing different attack patterns for testing IDS
#
# WARNING: Only run in isolated/test environments!
#

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║         IWSN Security - Attack PCAP Generator                  ║"
echo "║              FOR TESTING PURPOSES ONLY                         ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Create output directory
ATTACK_DIR="./attack_samples"
mkdir -p "$ATTACK_DIR"

echo "[*] Output directory: $ATTACK_DIR"
echo ""

# Check if tools are installed
echo "[*] Checking required tools..."

if ! command -v hping3 &> /dev/null; then
    echo "    [!] hping3 not found. Install: sudo apt-get install hping3"
    HPING3_AVAILABLE=0
else
    echo "    [✓] hping3 found"
    HPING3_AVAILABLE=1
fi

if ! command -v nmap &> /dev/null; then
    echo "    [!] nmap not found. Install: sudo apt-get install nmap"
    NMAP_AVAILABLE=0
else
    echo "    [✓] nmap found"
    NMAP_AVAILABLE=1
fi

if ! command -v tcpdump &> /dev/null; then
    echo "    [!] tcpdump not found. Install: sudo apt-get install tcpdump"
    exit 1
else
    echo "    [✓] tcpdump found"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Starting Attack PCAP Generation"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Target (localhost for safety)
TARGET="127.0.0.1"

# ========== 1. SYN Flood Attack ==========
if [ $HPING3_AVAILABLE -eq 1 ]; then
    echo "[1/9] Generating SYN Flood attack PCAP..."
    
    # Start packet capture
    sudo tcpdump -i lo -w "$ATTACK_DIR/syn_flood.pcap" port 8888 &
    TCPDUMP_PID=$!
    sleep 1
    
    # Generate SYN flood
    sudo hping3 -S -p 8888 --flood --count 2000 $TARGET > /dev/null 2>&1 &
    HPING_PID=$!
    
    sleep 3
    sudo kill $HPING_PID 2>/dev/null
    sleep 1
    sudo kill $TCPDUMP_PID 2>/dev/null
    
    echo "    [✓] Created: $ATTACK_DIR/syn_flood.pcap"
else
    echo "[1/9] Skipping SYN Flood (hping3 not available)"
fi

# ========== 2. UDP Flood Attack ==========
if [ $HPING3_AVAILABLE -eq 1 ]; then
    echo "[2/9] Generating UDP Flood attack PCAP..."
    
    sudo tcpdump -i lo -w "$ATTACK_DIR/udp_flood.pcap" port 9999 &
    TCPDUMP_PID=$!
    sleep 1
    
    # Generate UDP flood
    sudo hping3 --udp -p 9999 --flood --count 3000 $TARGET > /dev/null 2>&1 &
    HPING_PID=$!
    
    sleep 3
    sudo kill $HPING_PID 2>/dev/null
    sleep 1
    sudo kill $TCPDUMP_PID 2>/dev/null
    
    echo "    [✓] Created: $ATTACK_DIR/udp_flood.pcap"
else
    echo "[2/9] Skipping UDP Flood (hping3 not available)"
fi

# ========== 3. ICMP Flood Attack ==========
if [ $HPING3_AVAILABLE -eq 1 ]; then
    echo "[3/9] Generating ICMP Flood attack PCAP..."
    
    sudo tcpdump -i lo -w "$ATTACK_DIR/icmp_flood.pcap" icmp &
    TCPDUMP_PID=$!
    sleep 1
    
    # Generate ICMP flood
    sudo hping3 --icmp --flood --count 2000 $TARGET > /dev/null 2>&1 &
    HPING_PID=$!
    
    sleep 3
    sudo kill $HPING_PID 2>/dev/null
    sleep 1
    sudo kill $TCPDUMP_PID 2>/dev/null
    
    echo "    [✓] Created: $ATTACK_DIR/icmp_flood.pcap"
else
    echo "[3/9] Skipping ICMP Flood (hping3 not available)"
fi

# ========== 4. Ping of Death ==========
if [ $HPING3_AVAILABLE -eq 1 ]; then
    echo "[4/9] Generating Ping of Death attack PCAP..."
    
    sudo tcpdump -i lo -w "$ATTACK_DIR/ping_of_death.pcap" icmp &
    TCPDUMP_PID=$!
    sleep 1
    
    # Generate oversized ICMP packets (fragmented)
    for i in {1..20}; do
        sudo hping3 --icmp -d 65000 --count 1 $TARGET > /dev/null 2>&1
        sleep 0.1
    done
    
    sleep 1
    sudo kill $TCPDUMP_PID 2>/dev/null
    
    echo "    [✓] Created: $ATTACK_DIR/ping_of_death.pcap"
else
    echo "[4/9] Skipping Ping of Death (hping3 not available)"
fi

# ========== 5. TCP SYN Scan ==========
if [ $NMAP_AVAILABLE -eq 1 ]; then
    echo "[5/9] Generating TCP SYN Scan PCAP..."
    
    sudo tcpdump -i lo -w "$ATTACK_DIR/tcp_syn_scan.pcap" dst host $TARGET &
    TCPDUMP_PID=$!
    sleep 1
    
    # Perform SYN scan on common ports
    sudo nmap -sS -p 20-100 $TARGET > /dev/null 2>&1
    
    sleep 2
    sudo kill $TCPDUMP_PID 2>/dev/null
    
    echo "    [✓] Created: $ATTACK_DIR/tcp_syn_scan.pcap"
else
    echo "[5/9] Skipping TCP SYN Scan (nmap not available)"
fi

# ========== 6. TCP Connect Scan ==========
if [ $NMAP_AVAILABLE -eq 1 ]; then
    echo "[6/9] Generating TCP Connect Scan PCAP..."
    
    sudo tcpdump -i lo -w "$ATTACK_DIR/tcp_connect_scan.pcap" dst host $TARGET &
    TCPDUMP_PID=$!
    sleep 1
    
    # Perform TCP connect scan
    nmap -sT -p 20-100 $TARGET > /dev/null 2>&1
    
    sleep 2
    sudo kill $TCPDUMP_PID 2>/dev/null
    
    echo "    [✓] Created: $ATTACK_DIR/tcp_connect_scan.pcap"
else
    echo "[6/9] Skipping TCP Connect Scan (nmap not available)"
fi

# ========== 7. UDP Scan ==========
if [ $NMAP_AVAILABLE -eq 1 ]; then
    echo "[7/9] Generating UDP Scan PCAP..."
    
    sudo tcpdump -i lo -w "$ATTACK_DIR/udp_scan.pcap" dst host $TARGET &
    TCPDUMP_PID=$!
    sleep 1
    
    # Perform UDP scan
    sudo nmap -sU -p 20-100 $TARGET > /dev/null 2>&1
    
    sleep 2
    sudo kill $TCPDUMP_PID 2>/dev/null
    
    echo "    [✓] Created: $ATTACK_DIR/udp_scan.pcap"
else
    echo "[7/9] Skipping UDP Scan (nmap not available)"
fi

# ========== 8. HTTP Flood (Simulated) ==========
echo "[8/9] Generating HTTP Flood attack PCAP..."

# Create a simple HTTP flood using curl in background
sudo tcpdump -i lo -w "$ATTACK_DIR/http_flood.pcap" port 8080 &
TCPDUMP_PID=$!
sleep 1

# Start a simple HTTP server
python3 -m http.server 8080 > /dev/null 2>&1 &
HTTP_SERVER_PID=$!
sleep 1

# Generate HTTP requests rapidly
for i in {1..200}; do
    curl -s http://127.0.0.1:8080/ > /dev/null 2>&1 &
done
wait

sleep 2
sudo kill $TCPDUMP_PID 2>/dev/null
kill $HTTP_SERVER_PID 2>/dev/null

echo "    [✓] Created: $ATTACK_DIR/http_flood.pcap"

# ========== 9. Mixed Attack Traffic ==========
echo "[9/9] Generating Mixed Attack traffic PCAP..."

sudo tcpdump -i lo -w "$ATTACK_DIR/mixed_attacks.pcap" &
TCPDUMP_PID=$!
sleep 1

# Mix of different attacks
if [ $HPING3_AVAILABLE -eq 1 ]; then
    # Some SYN packets
    sudo hping3 -S -p 80 --count 100 --faster $TARGET > /dev/null 2>&1 &
    sleep 1
    
    # Some UDP packets
    sudo hping3 --udp -p 53 --count 100 --faster $TARGET > /dev/null 2>&1 &
    sleep 1
    
    # Some ICMP packets
    sudo hping3 --icmp --count 50 --faster $TARGET > /dev/null 2>&1 &
    sleep 1
fi

if [ $NMAP_AVAILABLE -eq 1 ]; then
    # Port scan
    nmap -sS -p 1-50 $TARGET > /dev/null 2>&1 &
fi

sleep 3
sudo kill $TCPDUMP_PID 2>/dev/null

echo "    [✓] Created: $ATTACK_DIR/mixed_attacks.pcap"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Attack PCAP Generation Complete!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Generated files:"
ls -lh "$ATTACK_DIR"/*.pcap 2>/dev/null
echo ""
echo "To analyze with IDS:"
echo "  ./bin/dpi_engine_ids $ATTACK_DIR/syn_flood.pcap"
echo "  ./bin/dpi_engine_ids $ATTACK_DIR/tcp_syn_scan.pcap"
echo ""
echo "WARNING: These PCAPs contain attack patterns."
echo "         Only use in isolated test environments!"
echo ""
