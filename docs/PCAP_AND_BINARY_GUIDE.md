# 📦 PCAP SAMPLES & BINARY GENERATION GUIDE

## Overview

This guide explains how to:
1. Generate/download sample PCAP files for testing
2. Compile the binaries from source code
3. Use pre-existing PCAPs if available

---

## 🎯 About Binaries

### ⚠️ Important: Binaries Are NOT Portable

**The `.o` object files and compiled binaries you uploaded are specific to your system and cannot be reused on a different machine.**

**Why?**
- Compiled for specific CPU architecture
- Linked against specific library versions
- Contain absolute paths from original build system

**Solution:** You must compile from source on your Ubuntu VM.

---

## 🔨 Compiling Binaries (REQUIRED)

### On Your Ubuntu VM:

```bash
# Navigate to project directory
cd ~/iwsn_security/c_dpi_engine

# Clean any old builds
make clean

# Compile both versions
make

# This creates:
#   bin/dpi_engine      (original DPI)
#   bin/dpi_engine_ids  (with IDS)
```

### Build Output:
```
Compiling src/main.c...
Compiling src/dpi_engine.c...
Compiling src/dpi_engine_flow.c...
Linking bin/dpi_engine...
✓ Build complete: bin/dpi_engine

Compiling src/main_with_ids.c...
Compiling src/rule_engine.c...
Compiling src/rule_engine_attacks.c...
Compiling src/rule_engine_report.c...
Linking bin/dpi_engine_ids...
✓ Build complete: bin/dpi_engine_ids
```

### Verify Compilation:
```bash
ls -lh bin/
# Should show:
# -rwxr-xr-x 1 user user 250K dpi_engine
# -rwxr-xr-x 1 user user 350K dpi_engine_ids

# Test execution
./bin/dpi_engine --help
./bin/dpi_engine_ids --help
```

---

## 📁 PCAP File Generation Methods

You have **3 methods** to get PCAP files:

### Method 1: Download Real Network Captures (RECOMMENDED)
### Method 2: Generate Attack Traffic (REQUIRES ROOT)
### Method 3: Create Synthetic PCAPs (SAFE, NO ROOT)

---

## Method 1: Download Sample PCAPs 🌐

**Easiest and safest method.**

### Using the Download Script:

```bash
# Make executable
chmod +x download_sample_pcaps.sh

# Run
./download_sample_pcaps.sh
```

### What You Get:
- mqtt.pcap - MQTT sensor communication
- http.cap - HTTP web traffic
- dns.cap - DNS queries
- dhcp.pcap - DHCP requests
- ftp.pcap - FTP file transfer
- telnet.pcap - Telnet session
- icmp.pcap - ICMP/Ping traffic
- tcp_handshake.pcap - TCP 3-way handshake
- arp.pcap - ARP traffic
- mixed_normal.pcap - Normal mixed traffic

### Manual Download:
```bash
mkdir -p pcap_samples
cd pcap_samples

# MQTT
wget https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mqtt.pcap

# HTTP
wget https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap

# DNS
wget https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap
```

---

## Method 2: Generate Attack Traffic 🔴

**⚠️ WARNING: Requires root, generates actual attack traffic**
**Only use in isolated test environments!**

### Prerequisites:
```bash
# Install required tools
sudo apt-get update
sudo apt-get install hping3 nmap tcpdump python3
```

### Using the Attack Generator Script:

```bash
# Make executable
chmod +x generate_attack_pcaps.sh

# Run (requires sudo)
sudo ./generate_attack_pcaps.sh
```

### What You Get:
- syn_flood.pcap - SYN flood attack
- udp_flood.pcap - UDP flood attack
- icmp_flood.pcap - ICMP flood attack
- ping_of_death.pcap - Oversized ICMP packets
- tcp_syn_scan.pcap - TCP SYN port scan
- tcp_connect_scan.pcap - TCP connect scan
- udp_scan.pcap - UDP port scan
- http_flood.pcap - HTTP flood attack
- mixed_attacks.pcap - Combined attacks

### Manual Generation Examples:

```bash
# SYN Flood
sudo tcpdump -i lo -w syn_flood.pcap port 8888 &
sudo hping3 -S -p 8888 --flood --count 2000 127.0.0.1
sudo killall tcpdump

# Port Scan
sudo tcpdump -i lo -w port_scan.pcap dst 127.0.0.1 &
nmap -sS -p 1-100 127.0.0.1
sudo killall tcpdump

# UDP Flood
sudo tcpdump -i lo -w udp_flood.pcap port 9999 &
sudo hping3 --udp -p 9999 --flood --count 3000 127.0.0.1
sudo killall tcpdump
```

---

## Method 3: Synthetic PCAP Generation 🔬

**SAFEST method - no actual network traffic generated**
**Uses Python + Scapy to create PCAP files**

### Prerequisites:
```bash
# Install Scapy
pip3 install scapy
# OR
sudo apt-get install python3-scapy
```

### Using the Synthetic Generator:

```bash
# Make executable
chmod +x generate_synthetic_pcaps.py

# Run
python3 generate_synthetic_pcaps.py
```

### What You Get:

**Normal Traffic:**
- normal_mixed.pcap - TCP/UDP/ICMP mix
- mqtt_sensor.pcap - MQTT sensor data

**Attack Traffic:**
- syn_flood.pcap - 2000 SYN packets
- udp_flood.pcap - 3000 UDP packets
- icmp_flood.pcap - 2000 ICMP packets
- ping_of_death.pcap - Oversized ICMP
- tcp_syn_scan.pcap - Port scan (50 ports)
- tcp_connect_scan.pcap - Full connect scan (30 ports)
- udp_scan.pcap - UDP scan (40 ports)
- http_flood.pcap - 300 HTTP requests

### Advantages:
- ✅ No root required
- ✅ No actual network traffic
- ✅ Completely safe
- ✅ Customizable packet patterns
- ✅ Deterministic output

### Customization:

Edit `generate_synthetic_pcaps.py` to change:
- Packet counts
- IP addresses
- Port ranges
- Attack intensity

---

## 🧪 Testing Your Setup

### Step 1: Generate/Download PCAPs

Choose one method above and get some PCAP files.

### Step 2: Test Original DPI

```bash
./bin/dpi_engine pcap_samples/mqtt.pcap
```

**Expected Output:**
- PCAP file analysis
- Flow statistics
- Protocol detection
- Packet details

### Step 3: Test IDS Version

```bash
./bin/dpi_engine_ids attack_samples/syn_flood.pcap
```

**Expected Output:**
- All of above PLUS
- Attack detection alerts
- Severity classification
- Attack summary report
- Generated report file

---

## 📊 Sample Directory Structure

After setup, your directory should look like:

```
iwsn_security/
├── c_dpi_engine/
│   ├── include/
│   │   ├── dpi_engine.h
│   │   └── rule_engine.h
│   ├── src/
│   │   ├── main.c
│   │   ├── main_with_ids.c
│   │   ├── dpi_engine.c
│   │   ├── dpi_engine_flow.c
│   │   ├── rule_engine.c
│   │   ├── rule_engine_attacks.c
│   │   └── rule_engine_report.c
│   ├── bin/
│   │   ├── dpi_engine           ← COMPILED ON YOUR SYSTEM
│   │   └── dpi_engine_ids       ← COMPILED ON YOUR SYSTEM
│   ├── obj/
│   │   └── *.o                  ← COMPILED ON YOUR SYSTEM
│   └── Makefile
│
├── pcap_samples/                ← NORMAL TRAFFIC
│   ├── mqtt.pcap
│   ├── http.cap
│   ├── dns.cap
│   ├── normal_mixed.pcap
│   └── ...
│
├── attack_samples/              ← ATTACK TRAFFIC
│   ├── syn_flood.pcap
│   ├── tcp_syn_scan.pcap
│   ├── udp_flood.pcap
│   └── ...
│
└── reports/                     ← GENERATED REPORTS
    ├── attack_report.txt
    └── ...
```

---

## 🎯 Quick Start Commands

### Complete Setup:

```bash
# 1. Build binaries
cd ~/iwsn_security/c_dpi_engine
make clean && make

# 2. Generate PCAPs (choose one)
python3 generate_synthetic_pcaps.py        # Safest
./download_sample_pcaps.sh                 # Real samples
sudo ./generate_attack_pcaps.sh            # Actual attacks

# 3. Test normal traffic
./bin/dpi_engine pcap_samples/mqtt.pcap

# 4. Test attack detection
./bin/dpi_engine_ids attack_samples/syn_flood.pcap report.txt

# 5. View report
cat report.txt
```

---

## 📝 PCAP File Sizes (Approximate)

### Normal Traffic:
- Small (1-10 KB): dns.cap, dhcp.pcap
- Medium (10-100 KB): mqtt.pcap, icmp.pcap
- Large (100KB-1MB): http.cap, mixed traffic

### Attack Traffic:
- SYN flood: ~100-200 KB
- UDP flood: ~150-300 KB
- Port scans: ~50-100 KB
- HTTP flood: ~200-400 KB

---

## ❓ FAQ

### Q: Can I use the .o files you provided?
**A:** No, they won't work on a different system. You must compile from source.

### Q: Where do I get the binaries?
**A:** Compile them yourself using `make` on your Ubuntu VM.

### Q: Do I need real network attacks for testing?
**A:** No! Use Method 3 (synthetic PCAPs) - it's safer and works perfectly.

### Q: Which PCAP generation method should I use?
**A:** 
- For learning: Method 3 (synthetic)
- For real traffic: Method 1 (download)
- For advanced testing: Method 2 (real attacks, careful!)

### Q: How do I know if attack detection is working?
**A:** Run `./bin/dpi_engine_ids attack_samples/syn_flood.pcap` and look for attack alerts in the output.

### Q: Can I create custom attack PCAPs?
**A:** Yes! Edit `generate_synthetic_pcaps.py` and customize the packet generation functions.

---

## 🔍 Verification Checklist

- [ ] Binaries compiled successfully (`bin/dpi_engine` exists)
- [ ] IDS binary compiled (`bin/dpi_engine_ids` exists)
- [ ] Sample PCAPs downloaded or generated
- [ ] Attack PCAPs available for testing
- [ ] Normal traffic analysis works
- [ ] Attack detection triggers correctly
- [ ] Reports are generated

---

## 🎉 You're Ready!

You now have:
- ✅ Source code (all .c and .h files)
- ✅ Build system (Makefile)
- ✅ PCAP generation scripts
- ✅ Instructions to compile binaries
- ✅ Sample traffic for testing

**No pre-compiled binaries needed - you compile them yourself!**

---

## 📞 Troubleshooting

### Compilation fails:
```bash
# Check nDPI installation
ndpiReader --version
sudo ldconfig

# Check dependencies
sudo apt-get install build-essential libpcap-dev

# Try clean build
make clean && make
```

### PCAP generation fails:
```bash
# For Method 2 - check tools
sudo apt-get install hping3 nmap tcpdump

# For Method 3 - check scapy
pip3 install --user scapy
```

### Binaries don't run:
```bash
# Check if they're executable
chmod +x bin/dpi_engine*

# Check library dependencies
ldd bin/dpi_engine_ids
```

---

**Happy Testing!** 🚀
