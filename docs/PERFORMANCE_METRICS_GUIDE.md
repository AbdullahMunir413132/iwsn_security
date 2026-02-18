# IWSN Security - Performance Metrics System

## Overview

The IWSN Security system includes a **comprehensive performance metrics tracking system** that monitors and reports detailed performance statistics for all modules:

- **DPI Engine** (Deep Packet Inspection - Layers 2-5)
- **Rule Engine** (Intrusion Detection System)
- **MQTT Parser** (Protocol-specific Analysis)

All analysis generates **four detailed text reports**:
1. **performance_metrics.txt** - System-wide performance and accuracy metrics
2. **dpi_packets_detailed.txt** - Packet-by-packet analysis with all 5 layers
3. **dpi_flows_detailed.txt** - Flow-by-flow statistics and protocol detection
4. **mqtt_packets_detailed.txt** - MQTT-specific analysis with payload dumps

## Features

### 📊 Tracked Metrics

#### DPI Engine Metrics
- **Timing**: Processing time, packets/second, MB/second
- **Layer Parsing**: L2/L3/L4/L5 parsing success rates (all layers)
- **Flow Management**: Flows created, average packets/bytes per flow
- **Protocol Detection**: Unique protocol types detected (not flow count), unknown protocols
- **Efficiency**: Time per packet/flow in microseconds
- **Memory Usage**: Flow and packet memory consumption

#### Rule Engine (IDS) Metrics
- **Timing**: Processing time, flows/second
- **Attack Detection**: Total attacks, breakdown by type
- **Detection Accuracy**: Precision, recall, accuracy (F1-score removed)
- **IP Tracking**: Unique IPs, blocked IPs, blocked packets
- **Attack Types**: SYN Flood, UDP Flood, HTTP Flood, ICMP Flood, Port Scans

#### MQTT Parser Metrics
- **Timing**: Processing time, messages/second
- **Flow Detection**: MQTT flows detected, detection rate
- **Message Parsing**: Success/failure rates
- **Message Types**: CONNECT, PUBLISH, SUBSCRIBE, etc.
- **Sensor Data**: Extraction rate
- **Anomalies**: Malformed packets, oversized packets

#### System-Wide Metrics
- **End-to-End Timing**: Total processing time
- **Pipeline Breakdown**: Time percentage per module
- **Overall Throughput**: System-wide packets/sec, MB/sec
- **PCAP Information**: File size, capture duration

## Usage

### Automatic Display

Performance metrics are **automatically displayed at the end of each run**:

```bash
./bin/dpi_mqtt_analyzer capture.pcap
```

Output includes:
1. **Summary Table** - Quick overview of all modules
2. **Timing Breakdown** - Pipeline time distribution
3. **Accuracy Table** - Attack detection accuracy (if available)

### Saved Metrics File

All metrics are automatically saved to `performance_metrics.txt` in the current directory.

**File Format:**
- Timestamped report header
- System overview (PCAP file info, total stats)
- Pretty-formatted tables
- Detailed metrics for each module

**Example:**
```bash
./bin/dpi_mqtt_analyzer attack.pcap
# Creates/updates performance_metrics.txt
```

### Viewing Metrics

```bash
# View the saved metrics
cat performance_metrics.txt

# View just the summary
head -40 performance_metrics.txt

# View timing details
grep -A 20 "PROCESSING TIME BREAKDOWN" performance_metrics.txt
```

## Output Examples

### Console Output

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                          PERFORMANCE METRICS SUMMARY TABLE                      ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ MODULE          │ TIME (ms) │  PACKETS  │   FLOWS   │ THROUGHPUT │ ACCURACY    ║
╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣
║ DPI Engine      │ 292.50 ms │       200 │       135 │    683 p/s │ L2:100%     ║
║                 │           │           │           │    0.03 MB/s│ L3:100%     ║
╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣
║ Rule Engine     │  0.328 ms │         0 │       135 │  411585 f/s│ Det:0.7%    ║
║ (IDS)           │           │           │         1 │            │ Prec:0.00%  ║
╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣
║ MQTT Parser     │  0.002 ms │         0 │         0 │       0 m/s│ Parse:0%    ║
║                 │           │  Messages │ MQTT Flows│            │ Sensor:0%   ║
╠═════════════════╪═══════════╪═══════════╪═══════════╪════════════╪═════════════╣
║ TOTAL SYSTEM    │ 292.96 ms │       200 │       135 │    683 p/s │ Overall     ║
║                 │           │           │           │    0.03 MB/s│ System      ║
╚═════════════════╧═══════════╧═══════════╧═══════════╧════════════╧═════════════╝
```

### Timing Breakdown

```
╔══════════════════════════════════════════════════════════════════════════╗
║                     PROCESSING TIME BREAKDOWN                            ║
╠══════════════════════════════════════════════════════════════════════════╣
║ Component        │ Time (ms)      │ Percentage │ Avg per Unit (µs)     ║
╠══════════════════╪════════════════╪════════════╪═══════════════════════╣
║ DPI Engine       │      292.50 ms │    99.85%   │ 1462.515 per packet  ║
║ Rule Engine      │       0.328 ms │     0.11%   │ 2.430 per flow       ║
║ MQTT Parser      │       0.002 ms │     0.00%   │ 0.000 per message    ║
║ Overhead         │       0.122 ms │     0.04%   │ N/A                  ║
╠══════════════════╪════════════════╪════════════╪═══════════════════════╣
║ TOTAL            │      292.96 ms │   100.00%  │                       ║
╚══════════════════╧════════════════╧════════════╧═══════════════════════╝
```

## Key Metrics Explained

### DPI Engine Metrics

| Metric | Description |
|--------|-------------|
| **L2 Parse Rate** | Percentage of packets successfully parsed at Data Link layer |
| **L3 Parse Rate** | Percentage of packets successfully parsed at Network layer |
| **L4 Parse Rate** | Percentage of packets successfully parsed at Transport layer |
| **L5 Parse Rate** | Percentage of packets with flow tracking (session layer) |
| **Protocol Detection Rate** | Percentage of unique protocols detected (not flows) |
| **Unique Protocols** | Count of distinct protocol types found (e.g., DNS, mDNS, HTTP) |
| **Avg Time per Packet** | Average microseconds spent processing each packet |
| **Memory Usage** | Total memory used for flow tracking and packet storage |

### Rule Engine Metrics

| Metric | Description |
|--------|-------------|
| **Attack Detection Rate** | Percentage of flows flagged as attacks |
| **Precision** | True Positives / (True Positives + False Positives) |
| **Recall** | True Positives / (True Positives + False Negatives) |
| **Accuracy** | (TP + TN) / (TP + TN + FP + FN) - Overall detection accuracy |
| **Flows per Second** | Rule engine throughput |

### MQTT Parser Metrics

| Metric | Description |
|--------|-------------|
| **MQTT Detection Rate** | Percentage of flows identified as MQTT |
| **Parse Success Rate** | Percentage of MQTT messages successfully parsed |
| **Sensor Extraction Rate** | Percentage of messages with extractable sensor data |
| **Messages per Second** | MQTT parsing throughput |

## Performance Optimization

### Interpreting Results

**Good Performance:**
- DPI: > 1000 packets/sec
- Rule Engine: > 100,000 flows/sec
- MQTT Parser: > 1000 messages/sec
- L2/L3/L4/L5 Parse Rate: > 95%
- Protocol Detection Rate: > 90%

**Performance Bottlenecks:**
- If DPI time > 95%: Packet processing is the bottleneck
- If Rule Engine time > 30%: Attack detection rules may need optimization
- High memory usage: Consider reducing max_flows or packet storage limits

### Troubleshooting

**Low Parse Rates:**
- Check PCAP file integrity
- Verify supported datalink types (DLT_EN10MB)
- Check for encrypted or malformed packets

**Low Protocol Detection:**
- nDPI may not recognize custom protocols
- Encrypted traffic appears as "Unknown"
- Insufficient packets for protocol detection (< 5 packets)

**High Processing Time:**
- Large PCAP files will take longer
- Attack floods (100k+ packets) trigger safety limits
- nDPI protocol detection overhead

## Integration with Other Tools

### Python Analysis

```python
import re

# Parse performance metrics from file
def parse_metrics(filename):
    with open(filename, 'r') as f:
        content = f.read()
        
    # Extract key values
    packets = re.search(r'Total Packets Processed:\s+(\d+)', content)
    time = re.search(r'Total Processing Time:\s+([\d.]+)', content)
    
    return {
        'packets': int(packets.group(1)),
        'time_ms': float(time.group(1))
    }

metrics = parse_metrics('performance_metrics.txt')
print(f"Throughput: {metrics['packets']/metrics['time_ms']*1000:.0f} packets/sec")
```

### Bash Scripting

```bash
#!/bin/bash
# Run analyzer and extract key metrics

./bin/dpi_mqtt_analyzer capture.pcap > /dev/null

# Extract metrics
PACKETS=$(grep "Total Packets:" performance_metrics.txt | awk '{print $3}')
TIME=$(grep "Total Processing Time:" performance_metrics.txt | awk '{print $4}')
ATTACKS=$(grep "Total Attacks:" performance_metrics.txt | awk '{print $3}')

echo "Analyzed $PACKETS packets in $TIME"
echo "Detected $ATTACKS attacks"
```

## File Locations

| File | Description |
|------|-------------|
| `include/performance_metrics.h` | Header file with data structures |
| `src/performance_metrics.c` | Implementation of metrics tracking |
| `performance_metrics.txt` | Saved metrics report (created at runtime) |

## API Reference

### Initialization Functions

```c
void perf_metrics_init(system_performance_t *metrics);
void perf_dpi_init(dpi_performance_t *metrics);
void perf_rule_engine_init(rule_engine_performance_t *metrics);
void perf_mqtt_parser_init(mqtt_parser_performance_t *metrics);
```

### Update Functions

```c
void perf_dpi_update(dpi_performance_t *metrics, const void *dpi_engine);
void perf_rule_engine_update(rule_engine_performance_t *metrics, const void *rule_engine);
void perf_mqtt_parser_update(mqtt_parser_performance_t *metrics, ...);
```

### Finalization Functions

```c
void perf_dpi_finalize(dpi_performance_t *metrics);
void perf_rule_engine_finalize(rule_engine_performance_t *metrics);
void perf_mqtt_parser_finalize(mqtt_parser_performance_t *metrics);
void perf_system_finalize(system_performance_t *metrics);
```

### Display Functions

```c
void perf_print_all_metrics_table(const system_performance_t *metrics);
void perf_print_summary_table(const system_performance_t *metrics);
void perf_print_timing_breakdown_table(const system_performance_t *metrics);
```

### File I/O Functions

```c
void perf_save_metrics_to_file(const system_performance_t *metrics, const char *filename);
void perf_append_metrics_to_file(const system_performance_t *metrics, const char *filename);
```

## Benefits

✅ **Comprehensive Tracking** - All modules monitored automatically
✅ **Pretty Output** - Beautiful ASCII tables for easy reading
✅ **File Persistence** - Metrics saved for later analysis
✅ **Zero Configuration** - Works out-of-the-box
✅ **Performance Insights** - Identify bottlenecks quickly
✅ **Accuracy Tracking** - Monitor IDS detection quality
✅ **Historical Analysis** - Compare runs over time

## Future Enhancements

- [ ] JSON output format for programmatic analysis
- [ ] Real-time metrics dashboard
- [ ] Historical metrics database
- [ ] Performance regression testing
- [ ] Configurable metrics output
- [ ] Per-protocol metrics breakdown
- [ ] Network-wide aggregation

## Support

For questions or issues related to performance metrics:
1. Check the metrics file: `performance_metrics.txt`
2. Review the console output tables
3. Verify all modules are running correctly
4. Check PCAP file format and integrity

---

**Last Updated:** February 10, 2026
**Version:** 1.0
