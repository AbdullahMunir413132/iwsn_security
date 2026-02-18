# 🚀 COMPLETE INSTALLATION & TESTING GUIDE

## Step-by-Step Instructions for Ubuntu VM

### STEP 1: Transfer Files to Ubuntu VM

**Option A: If using shared folder**
```bash
# On Ubuntu VM
cd ~
mkdir -p iwsn_security/c_dpi_engine/{include,src}
```

**Option B: If using SCP from Windows**
```bash
# On Windows (PowerShell/CMD)
scp -r c_dpi_engine user@ubuntu-vm-ip:~/iwsn_security/
```

### STEP 2: Organize the New Files

```bash
cd ~/iwsn_security/c_dpi_engine

# Create include directory if it doesn't exist
mkdir -p include src

# Move header files
mv rule_engine.h include/

# Move source files
mv main_with_ids.c src/
mv rule_engine.c src/
mv rule_engine_attacks.c src/
mv rule_engine_report.c src/

# Copy/update Makefile
# (You should have the new Makefile in the directory)

# File structure should now be:
# c_dpi_engine/
# ├── include/
# │   ├── dpi_engine.h
# │   └── rule_engine.h
# ├── src/
# │   ├── main.c
# │   ├── main_with_ids.c
# │   ├── dpi_engine.c
# │   ├── dpi_engine_flow.c
# │   ├── rule_engine.c
# │   ├── rule_engine_attacks.c
# │   └── rule_engine_report.c
# └── Makefile
```

### STEP 3: Verify nDPI Installation

```bash
# Check nDPI version
ndpiReader --version
# Should show: nDPI version 5.1.0-5606-73d2c86

# Find nDPI library
find /usr -name "libndpi.so*" 2>/dev/null

# Find nDPI headers
find /usr -name "ndpi_main.h" 2>/dev/null

# Update library cache
sudo ldconfig
```

### STEP 4: Build the Project

```bash
cd ~/iwsn_security/c_dpi_engine

# Clean any old builds
make clean

# Build both versions (DPI + IDS)
make

# You should see:
# Compiling src/main_with_ids.c...
# Compiling src/dpi_engine.c...
# Compiling src/dpi_engine_flow.c...
# Compiling src/rule_engine.c...
# Compiling src/rule_engine_attacks.c...
# Compiling src/rule_engine_report.c...
# Linking bin/dpi_engine_ids...
# ✓ Build complete: bin/dpi_engine_ids
# Compiling src/main.c...
# Linking bin/dpi_engine...
# ✓ Build complete: bin/dpi_engine

# Verify binaries were created
ls -lh bin/
# Should show:
# -rwxr-xr-x 1 user user 250K Jan 28 10:00 dpi_engine
# -rwxr-xr-x 1 user user 350K Jan 28 10:00 dpi_engine_ids
```

### STEP 5: Get Sample PCAP Files

**Option A: Download sample MQTT traffic**
```bash
cd ~/iwsn_security
mkdir -p pcap_samples attack_samples

cd pcap_samples

# Download sample PCAP files
wget https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mqtt.pcap
wget https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap
wget https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap
```

**Option B: Capture your own traffic**
```bash
cd ~/iwsn_security/pcap_samples

# Capture 100 packets from any interface
sudo tcpdump -i any -w test_capture.pcap -c 100

# Capture HTTP traffic
sudo tcpdump -i any -w http_test.pcap port 80 -c 50

# Capture DNS traffic
sudo tcpdump -i any -w dns_test.pcap port 53 -c 50
```

**Option C: Generate attack traffic for testing**
```bash
# Install hping3 for generating attack traffic
sudo apt-get install hping3

# Generate SYN flood (TESTING ONLY - be careful!)
# In one terminal:
sudo tcpdump -i lo -w ~/iwsn_security/attack_samples/syn_flood.pcap port 8888 &

# In another terminal (attack localhost):
sudo hping3 -S -p 8888 --flood --count 1000 127.0.0.1

# Stop tcpdump after a few seconds
sudo killall tcpdump
```

### STEP 6: Run the DPI + IDS System

```bash
cd ~/iwsn_security/c_dpi_engine

# Test with original DPI (no attack detection)
./bin/dpi_engine ../pcap_samples/mqtt.pcap

# Test with IDS (with attack detection)
./bin/dpi_engine_ids ../pcap_samples/mqtt.pcap

# Generate attack report
./bin/dpi_engine_ids ../pcap_samples/mqtt.pcap mqtt_analysis_report.txt

# Test with attack PCAP (if you generated one)
./bin/dpi_engine_ids ../attack_samples/syn_flood.pcap syn_flood_report.txt
```

### STEP 7: Verify Output

**Expected output sections:**

1. **Initialization**
```
╔════════════════════════════════════════════════════════════════╗
║         IWSN SECURITY - DPI ENGINE + IDS v3.0                  ║
║   Deep Packet Inspection + Intrusion Detection System         ║
╚════════════════════════════════════════════════════════════════╝

[Step 1/4] Initializing DPI Engine...
[DPI Engine] Initialized with max_flows=10000
[DPI Engine] nDPI version: 5.1.0-5606-73d2c86

[Step 2/4] Initializing Intrusion Detection System...
[Rule Engine] Initialized successfully
[Rule Engine] Max IPs: 10000, Max Detections: 1000
[Rule Engine] Default thresholds loaded
```

2. **Processing**
```
[Step 3/4] Processing PCAP file and detecting attacks...
[PCAP] Opening file: mqtt.pcap
[PCAP] Datalink type: EN10MB
[PCAP] Processing packets and analyzing for attacks...
  ... processed 1000 packets, 25 flows, 0 attacks detected
```

3. **Attack Summary** (if attacks found)
```
╔════════════════════════════════════════════════════════════════╗
║              INTRUSION DETECTION SUMMARY REPORT                ║
╚════════════════════════════════════════════════════════════════╝

[ANALYSIS OVERVIEW]
Total Packets Analyzed: 1000
Total Attacks Detected: 3
Unique IP Addresses: 10

[ATTACKS BY TYPE]
SYN Flood             : 1
TCP SYN Scan          : 2
```

4. **Detailed Attack Information**
```
╔════════════════════════════════════════════════════════════════╗
║  ⚠️  ATTACK DETECTED - HIGH
╚════════════════════════════════════════════════════════════════╝

[ATTACK INFORMATION]
  Attack Type:     SYN Flood Attack
  Description:     High rate of SYN packets detected
  Confidence:      87.50%

[SOURCE & TARGET]
  Attacker IP:     192.168.1.100:12345
  Target IP:       192.168.1.200:80
  Protocol:        TCP (6)

[ATTACK METRICS]
  Packet Count:    500 packets
  Byte Count:      30000 bytes (29.30 KB)
  Packet Rate:     125.00 packets/second
  Duration:        4.00 seconds
```

### STEP 8: Check Generated Report

```bash
# View the text report
cat mqtt_analysis_report.txt

# Or use less for better viewing
less mqtt_analysis_report.txt

# Report should contain:
# - Summary of analysis
# - Attacks by type
# - Detailed detection information
# - Timestamps and metrics
```

### STEP 9: Test Different Attack Scenarios

```bash
# Create test script
cat > test_all_attacks.sh << 'EOF'
#!/bin/bash

cd ~/iwsn_security/c_dpi_engine

echo "Testing DPI + IDS System with various PCAP files..."

for pcap in ../pcap_samples/*.pcap; do
    echo ""
    echo "=========================================="
    echo "Analyzing: $(basename $pcap)"
    echo "=========================================="
    
    report="report_$(basename $pcap .pcap).txt"
    ./bin/dpi_engine_ids "$pcap" "$report"
    
    echo "Report saved to: $report"
done

echo ""
echo "All tests completed!"
EOF

chmod +x test_all_attacks.sh
./test_all_attacks.sh
```

## 🎯 VERIFICATION CHECKLIST

After installation, verify these items:

- [ ] nDPI 5.1.0 is installed (`ndpiReader --version`)
- [ ] libpcap-dev is installed
- [ ] All source files are in correct directories
- [ ] `make` completes without errors
- [ ] `bin/dpi_engine` binary created
- [ ] `bin/dpi_engine_ids` binary created
- [ ] Program runs without crashing
- [ ] PCAP files are processed successfully
- [ ] Flow information is displayed
- [ ] Protocol detection works (MQTT, HTTP, etc.)
- [ ] Attack detection triggers on malicious traffic
- [ ] Report files are generated
- [ ] No memory leaks (run with valgrind if available)

## 🔧 COMMON ISSUES & FIXES

### Issue 1: "Cannot find ndpi_main.h"
```bash
# Find where nDPI headers are installed
find /usr -name "ndpi_main.h" 2>/dev/null

# If found in /usr/include/ndpi/
# Update Makefile CFLAGS to include: -I/usr/include/ndpi

# If found in /usr/local/include/ndpi/
# Update Makefile CFLAGS to include: -I/usr/local/include/ndpi
```

### Issue 2: "Cannot find libndpi.so"
```bash
# Find library location
find /usr -name "libndpi.so*" 2>/dev/null

# Update library cache
sudo ldconfig

# If still not found, add to LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
echo 'export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH' >> ~/.bashrc
```

### Issue 3: Compilation errors
```bash
# Clean and rebuild
make clean
make

# Check gcc version (should be 7+)
gcc --version

# Install missing dependencies
sudo apt-get install build-essential libpcap-dev
```

### Issue 4: Segmentation fault
```bash
# Run with debugging
gdb ./bin/dpi_engine_ids
(gdb) run test.pcap
(gdb) backtrace

# Or check with valgrind
valgrind --leak-check=full ./bin/dpi_engine_ids test.pcap
```

### Issue 5: No attacks detected on attack PCAP
```bash
# Lower thresholds in src/rule_engine.c
# Rebuild and test again

# Check if PCAP actually contains attacks
tcpdump -r attack.pcap -c 10
```

## 📊 SAMPLE OUTPUT EXAMPLES

### Normal Traffic (No Attacks)
```
[ANALYSIS OVERVIEW]
  Total Packets Analyzed:    500
  Total Attacks Detected:    0
  Unique IP Addresses:       5

  ✓ No attacks detected. Traffic appears normal.
```

### SYN Flood Detected
```
[ATTACKS BY TYPE]
  SYN Flood             : 1

[SEVERITY DISTRIBUTION]
  🟠 HIGH     : 1

[TOP ATTACKERS]
  1. 192.168.1.100 - 1 attacks

╔════════════════════════════════════════════════════════════════╗
║  ⚠️  ATTACK DETECTED - HIGH
╚════════════════════════════════════════════════════════════════╝

[ATTACK INFORMATION]
  Attack Type:     SYN Flood Attack
  Description:     High rate of SYN packets detected (125.00 SYN/sec)
```

### Port Scan Detected
```
[ATTACKS BY TYPE]
  TCP SYN Scan          : 1

[ATTACK INFORMATION]
  Attack Type:     TCP SYN Scan (Port Scanning)
  Description:     TCP SYN scan detected targeting 25 ports
  
[ADDITIONAL DETAILS]
  SYN: 25, RST: 20, ACK: 5, Unique Ports: 25. 
  Pattern matches stealthy SYN scan.
```

## 🎓 NEXT STEPS

After successful installation:

1. **Test with Your Own Traffic**
   - Capture real network traffic from your IWSN
   - Analyze with the IDS system
   - Adjust thresholds based on results

2. **Generate Custom Attacks**
   - Use hping3, nmap for testing
   - Create PCAP files of various attack types
   - Verify detection accuracy

3. **Fine-tune Thresholds**
   - Adjust detection thresholds in `rule_engine.c`
   - Rebuild and test
   - Find optimal balance for your network

4. **Convert to Real-time**
   - Modify to use `pcap_open_live()` instead of `pcap_open_offline()`
   - Run on actual network interface
   - Implement alerting mechanisms

5. **Integrate with SDN Controller**
   - Add REST API client
   - Send alerts to controller
   - Implement automated blocking

---

**Installation Complete! 🎉**

You now have a fully functional DPI + IDS system for IWSN security analysis.
