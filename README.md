# IWSN Security - DPI Engine with Intrusion Detection System

[![C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![nDPI](https://img.shields.io/badge/powered%20by-nDPI-orange.svg)](https://github.com/ntop/nDPI)

A comprehensive **Deep Packet Inspection (DPI) Engine** with integrated **Intrusion Detection System (IDS)** designed for Industrial Wireless Sensor Networks (IWSN). Features complete Layer 2-7 network analysis, attack detection, and MQTT integration for real-time security monitoring.

## 🚀 Features

### Deep Packet Inspection
- **Multi-Layer Analysis**: Complete Layer 2-5 parsing + partial Layer 7 protocol detection
- **Flow Tracking**: Advanced 5-tuple flow management with timeout handling
- **Protocol Detection**: Powered by nDPI for application-layer protocol identification
- **MQTT Support**: Full MQTT protocol parsing and analysis

### Intrusion Detection System
- **Attack Detection**: Real-time detection of multiple attack types:
  - SYN Flood & TCP attacks
  - UDP Flood attacks
  - ICMP Flood & Ping of Death
  - Port scanning (TCP SYN/Connect scans, UDP scans)
  - HTTP Flood attacks
- **Adaptive Thresholds**: Configurable detection thresholds per attack type
- **Flow-Based Analysis**: Statistical analysis of network flows
- **Comprehensive Reporting**: Detailed attack reports with severity levels

### MQTT Integration
- **Real-Time Alerts**: Publish security events to MQTT broker
- **Bidirectional Communication**: Subscribe to control commands
- **JSON Formatting**: Structured data for easy integration
- **Configurable Topics**: Customizable MQTT topic structure

## 📋 Requirements

### Dependencies
- **gcc** (GCC 7.0 or higher)
- **libpcap** - Packet capture library
- **nDPI** - Network protocol detection library
- **Paho MQTT C** - MQTT client library
- **pthread** - POSIX threads
- **libm** - Math library

### Installation (Ubuntu/Debian)

```bash
# Install basic dependencies
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev git autoconf automake libtool pkg-config

# Install nDPI
git clone https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure
make
sudo make install
sudo ldconfig
cd ..

# Install Paho MQTT C
git clone https://github.com/eclipse/paho.mqtt.c.git
cd paho.mqtt.c
make
sudo make install
sudo ldconfig
cd ..
```

For detailed installation instructions, see [INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md).

## 🛠️ Building

```bash
cd c_dpi_engine

# Build all targets
make all

# Build specific targets
make dpi_engine          # DPI engine only
make dpi_engine_ids      # DPI + IDS integrated
make dpi_mqtt_analyzer   # DPI + Rule Engine + MQTT

# Clean build artifacts
make clean
```

## 🎯 Usage

### Basic DPI Analysis
```bash
./bin/dpi_engine ../scripts/pcap_samples/normal_mixed.pcap
```

### DPI with IDS
```bash
./bin/dpi_engine_ids ../scripts/attack_samples/syn_flood.pcap
```

### Full System with MQTT
```bash
./bin/dpi_mqtt_analyzer ../scripts/pcap_samples/mqtt_sensor.pcap
```

### Analyzing Attack Traffic
```bash
# Test different attack types
./bin/dpi_engine_ids ../scripts/attack_samples/syn_flood.pcap
./bin/dpi_engine_ids ../scripts/attack_samples/udp_flood.pcap
./bin/dpi_engine_ids ../scripts/attack_samples/tcp_syn_scan.pcap
```

## 📂 Project Structure

```
iwsn_security/
├── c_dpi_engine/           # Core DPI engine and IDS
│   ├── include/           # Header files
│   ├── src/              # Source files
│   ├── bin/              # Compiled binaries
│   ├── obj/              # Object files
│   └── Makefile          # Build configuration
├── scripts/              # Utilities and sample data
│   ├── pcap_samples/     # Normal traffic samples
│   ├── attack_samples/   # Attack traffic samples
│   └── *.sh, *.py       # Helper scripts
└── docs/                 # Comprehensive documentation
    ├── IDS_README.md
    ├── INSTALLATION_GUIDE.md
    ├── ATTACK_DETECTION_REFERENCE.md
    └── more...
```

## 📖 Documentation

- [Installation Guide](docs/INSTALLATION_GUIDE.md) - Detailed setup instructions
- [IDS Documentation](docs/IDS_README.md) - Intrusion detection system details
- [Attack Detection Reference](docs/ATTACK_DETECTION_REFERENCE.md) - Supported attacks and thresholds
- [File Structure Guide](docs/FILE_STRUCTURE_GUIDE.md) - Complete project structure
- [PCAP and Binary Guide](docs/PCAP_AND_BINARY_GUIDE.md) - Working with packet captures

## 🔬 Testing with Sample PCAPs

The project includes various sample PCAP files for testing:

### Normal Traffic
- `mqtt_sensor.pcap` - MQTT sensor data
- `normal_mixed.pcap` - Mixed protocol traffic

### Attack Samples
- `syn_flood.pcap` - SYN flood attack
- `udp_flood.pcap` - UDP flood attack
- `icmp_flood.pcap` - ICMP flood attack
- `ping_of_death.pcap` - Ping of Death attack
- `tcp_syn_scan.pcap` - TCP SYN port scan
- `tcp_connect_scan.pcap` - TCP Connect scan
- `udp_scan.pcap` - UDP port scan
- `http_flood.pcap` - HTTP flood attack

Generate additional test data:
```bash
cd scripts
./generate_attack_pcaps.sh          # Generate attack samples
python3 generate_synthetic_pcaps.py  # Generate synthetic traffic
```

## 🔧 Configuration

### IDS Thresholds
Edit threshold values in [src/rule_engine_attacks.c](c_dpi_engine/src/rule_engine_attacks.c):

```c
#define SYN_FLOOD_THRESHOLD 100
#define UDP_FLOOD_THRESHOLD 150
#define PORT_SCAN_THRESHOLD 20
// ... and more
```

### MQTT Configuration
Configure MQTT broker settings in [src/mqtt_integration.c](c_dpi_engine/src/mqtt_integration.c):

```c
#define MQTT_BROKER "tcp://localhost:1883"
#define MQTT_CLIENT_ID "iwsn_dpi_engine"
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [nDPI](https://github.com/ntop/nDPI) - Network protocol detection library
- [Eclipse Paho](https://www.eclipse.org/paho/) - MQTT client libraries
- [libpcap](https://www.tcpdump.org/) - Packet capture library

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**Note**: This project is designed for research and educational purposes in industrial network security.
