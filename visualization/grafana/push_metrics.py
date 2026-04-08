#!/usr/bin/env python3
"""
IWSN Security - Grafana Metrics Exporter
Parses DPI/IDS/MQTT report files and pushes metrics to InfluxDB
for real-time Grafana dashboard visualization.

Usage:
    # One-shot mode (after PCAP analysis):
    python3 push_metrics.py ../c_dpi_engine

    # Continuous mode (for live capture monitoring):
    python3 push_metrics.py ../c_dpi_engine --watch
"""

import os
import re
import sys
import time
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    from influxdb_client import InfluxDBClient, Point, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS
    INFLUXDB_AVAILABLE = True
except ImportError:
    INFLUXDB_AVAILABLE = False

# InfluxDB connection settings (match docker-compose.yml)
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_TOKEN = "iwsn-security-influxdb-token"
INFLUXDB_ORG = "iwsn"
INFLUXDB_BUCKET = "iwsn_metrics"


class ReportParser:
    """Parse DPI/IDS/MQTT text report files into structured metrics."""

    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.metrics = {}

    def parse_all(self):
        """Parse all report files and return metrics dict."""
        self.parse_performance()
        self.parse_ids()
        self.parse_mqtt()
        return self.metrics

    def parse_performance(self):
        """Parse performance_metrics.txt"""
        filepath = self.base_dir / 'performance_metrics.txt'
        if not filepath.exists():
            print(f"  [WARN] Not found: {filepath}")
            return

        content = filepath.read_text()

        self.metrics['dpi'] = {
            'total_packets': self._extract_int(content, r'Total Packets Processed:\s+([\d,]+)'),
            'total_flows': self._extract_int(content, r'Total Flows Tracked:\s+([\d,]+)'),
            'throughput_pps': self._extract_int(content, r'Overall Throughput:\s+([\d,]+)\s+packets/sec'),
            'processing_time_ms': self._extract_float(content, r'Total Processing Time:\s+([\d.]+)\s+ms'),
            'data_bytes_mb': self._extract_float(content, r'Total Bytes Processed:\s+([\d.]+)\s+MB'),
            'protocols_detected': self._extract_int(content, r'Detected Protocols:\s+(\d+)'),
            'detection_rate': self._extract_float(content, r'Detection Rate:\s+([\d.]+)%'),
        }

        # Layer parsing rates
        self.metrics['dpi_layers'] = {
            'layer2_rate': self._extract_float(content, r'Layer 2.*?:\s+([\d.]+)%'),
            'layer3_rate': self._extract_float(content, r'Layer 3.*?:\s+([\d.]+)%'),
            'layer4_rate': self._extract_float(content, r'Layer 4.*?:\s+([\d.]+)%'),
            'layer5_rate': self._extract_float(content, r'Layer 5.*?:\s+([\d.]+)%'),
        }

        # System metrics
        self.metrics['system'] = {
            'cpu_usage': min(self._extract_float(content, r'CPU Usage:\s+([\d.]+)%'), 100.0),
            'memory_usage': self._extract_float(content, r'Memory Usage:\s+([\d.]+)'),
        }

        # Accuracy metrics
        self.metrics['ids_accuracy'] = {
            'precision': self._extract_float(content, r'Precision:\s+([\d.]+)%'),
            'recall': self._extract_float(content, r'Recall:\s+([\d.]+)%'),
            'accuracy': self._extract_float(content, r'Accuracy:\s+([\d.]+)%'),
        }

        # PCAP file info
        pcap_match = re.search(r'PCAP File:\s+(.+)', content)
        self.metrics['pcap_file'] = pcap_match.group(1).strip() if pcap_match else 'Unknown'

        print(f"  [OK] Parsed performance_metrics.txt")

    def parse_ids(self):
        """Parse ids_detailed_report.txt"""
        filepath = self.base_dir / 'ids_detailed_report.txt'
        if not filepath.exists():
            print(f"  [WARN] Not found: {filepath}")
            return

        content = filepath.read_text()

        self.metrics['ids'] = {
            'total_attacks': self._extract_int(content, r'Attacks Detected:\s+(\d+)'),
            'blocked_ips': self._extract_int(content, r'Blocked IPs:\s+(\d+)'),
            'flows_analyzed': self._extract_int(content, r'Flows Analyzed:\s+(\d+)'),
        }

        self.metrics['attacks'] = {
            'syn_flood': self._extract_int(content, r'SYN Flood Attacks\s+:\s+(\d+)'),
            'udp_flood': self._extract_int(content, r'UDP Flood Attacks\s+:\s+(\d+)'),
            'http_flood': self._extract_int(content, r'HTTP Flood Attacks\s+:\s+(\d+)'),
            'icmp_flood': self._extract_int(content, r'ICMP Flood Attacks\s+:\s+(\d+)'),
            'tcp_syn_scan': self._extract_int(content, r'TCP SYN Scan\s+:\s+(\d+)'),
            'tcp_connect_scan': self._extract_int(content, r'TCP Connect Scan\s+:\s+(\d+)'),
            'rudy_attack': self._extract_int(content, r'RUDY \(Slow POST\)\s+:\s+(\d+)'),
        }

        # Extract blocked IP list
        blocked_section = re.search(r'Blocked IP Addresses:(.*?)(?:\n\n|═)', content, re.DOTALL)
        if blocked_section:
            self.metrics['blocked_ip_list'] = re.findall(r'•\s+([\d.]+)', blocked_section.group(1))
        else:
            self.metrics['blocked_ip_list'] = []

        print(f"  [OK] Parsed ids_detailed_report.txt")

    def parse_mqtt(self):
        """Parse mqtt_packets_detailed.txt"""
        filepath = self.base_dir / 'mqtt_packets_detailed.txt'
        if not filepath.exists():
            print(f"  [WARN] Not found: {filepath}")
            return

        content = filepath.read_text()

        self.metrics['mqtt'] = {
            'mqtt_flows': self._extract_int(content, r'MQTT Flows:\s+(\d+)'),
            'messages_parsed': self._extract_int(content, r'MQTT Packets:\s+(\d+)'),
            'sensor_data_extracted': self._extract_int(content, r'Sensor Data:\s+(\d+)'),
        }

        print(f"  [OK] Parsed mqtt_packets_detailed.txt")

    def _extract_int(self, text, pattern):
        match = re.search(pattern, text)
        if match:
            return int(match.group(1).replace(',', ''))
        return 0

    def _extract_float(self, text, pattern):
        match = re.search(pattern, text)
        if match:
            return float(match.group(1))
        return 0.0


class InfluxDBExporter:
    """Push parsed metrics to InfluxDB for Grafana consumption."""

    def __init__(self):
        if not INFLUXDB_AVAILABLE:
            raise RuntimeError(
                "influxdb-client package not installed.\n"
                "Install with: pip3 install influxdb-client"
            )
        self.client = InfluxDBClient(
            url=INFLUXDB_URL,
            token=INFLUXDB_TOKEN,
            org=INFLUXDB_ORG
        )
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)

    def push_metrics(self, metrics):
        """Write all metrics to InfluxDB."""
        now = datetime.now(timezone.utc)
        points = []

        # DPI Metrics
        if 'dpi' in metrics:
            for field, value in metrics['dpi'].items():
                p = Point("dpi_metrics").field(field, value).time(now, WritePrecision.S)
                points.append(p)

        # DPI Layer Metrics
        if 'dpi_layers' in metrics:
            for field, value in metrics['dpi_layers'].items():
                p = Point("dpi_layer_metrics").field(field, value).time(now, WritePrecision.S)
                points.append(p)

        # System Metrics
        if 'system' in metrics:
            for field, value in metrics['system'].items():
                p = Point("system_metrics").field(field, value).time(now, WritePrecision.S)
                points.append(p)

        # IDS Metrics
        if 'ids' in metrics:
            for field, value in metrics['ids'].items():
                p = Point("ids_metrics").field(field, value).time(now, WritePrecision.S)
                points.append(p)

        # Attack Metrics
        if 'attacks' in metrics:
            for field, value in metrics['attacks'].items():
                p = Point("attack_metrics").field(field, value).time(now, WritePrecision.S)
                points.append(p)

        # IDS Accuracy
        if 'ids_accuracy' in metrics:
            for field, value in metrics['ids_accuracy'].items():
                p = Point("ids_accuracy").field(field, value).time(now, WritePrecision.S)
                points.append(p)

        # MQTT Metrics
        if 'mqtt' in metrics:
            for field, value in metrics['mqtt'].items():
                p = Point("mqtt_metrics").field(field, value).time(now, WritePrecision.S)
                points.append(p)

        # Write all points
        self.write_api.write(bucket=INFLUXDB_BUCKET, record=points)
        print(f"  [OK] Pushed {len(points)} data points to InfluxDB")

    def close(self):
        self.client.close()


def run_oneshot(base_dir):
    """Parse reports once and push to InfluxDB."""
    print("=" * 70)
    print("  IWSN Security - Grafana Metrics Exporter (One-Shot)")
    print("=" * 70)
    print(f"  Reports directory: {base_dir}\n")

    parser = ReportParser(base_dir)
    metrics = parser.parse_all()

    if not metrics:
        print("\n  [ERROR] No metrics parsed. Check report files exist.")
        return False

    print(f"\n  Pushing metrics to InfluxDB ({INFLUXDB_URL})...")
    exporter = InfluxDBExporter()
    exporter.push_metrics(metrics)
    exporter.close()

    print(f"\n  Done! Open Grafana at http://localhost:3000")
    print(f"  Login: admin / iwsn_security")
    print("=" * 70)
    return True


def run_watch(base_dir, interval=5):
    """Continuously watch report files and push updates to InfluxDB."""
    print("=" * 70)
    print("  IWSN Security - Grafana Metrics Exporter (Watch Mode)")
    print("=" * 70)
    print(f"  Reports directory: {base_dir}")
    print(f"  Poll interval: {interval}s")
    print(f"  Press Ctrl+C to stop\n")

    exporter = InfluxDBExporter()
    last_mtime = {}
    iteration = 0

    try:
        while True:
            iteration += 1
            changed = False
            report_files = [
                'performance_metrics.txt',
                'ids_detailed_report.txt',
                'mqtt_packets_detailed.txt'
            ]

            for fname in report_files:
                fpath = Path(base_dir) / fname
                if fpath.exists():
                    mtime = fpath.stat().st_mtime
                    if fname not in last_mtime or last_mtime[fname] != mtime:
                        last_mtime[fname] = mtime
                        changed = True

            if changed or iteration == 1:
                ts = datetime.now().strftime('%H:%M:%S')
                print(f"  [{ts}] Reports changed - parsing & pushing metrics...")
                parser = ReportParser(base_dir)
                metrics = parser.parse_all()
                if metrics:
                    exporter.push_metrics(metrics)
            else:
                if iteration % 12 == 0:  # Print heartbeat every ~60s
                    ts = datetime.now().strftime('%H:%M:%S')
                    print(f"  [{ts}] Watching for changes...")

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n  Stopped. Grafana dashboard remains available at http://localhost:3000")
    finally:
        exporter.close()


def main():
    arg_parser = argparse.ArgumentParser(
        description='IWSN Security - Push DPI/IDS/MQTT metrics to Grafana via InfluxDB'
    )
    arg_parser.add_argument(
        'base_dir',
        nargs='?',
        default=os.path.join(os.path.dirname(__file__), '..', 'c_dpi_engine'),
        help='Directory containing report .txt files (default: ../c_dpi_engine)'
    )
    arg_parser.add_argument(
        '--watch', '-w',
        action='store_true',
        help='Continuously watch for report file changes and push updates'
    )
    arg_parser.add_argument(
        '--interval', '-i',
        type=int,
        default=5,
        help='Watch mode poll interval in seconds (default: 5)'
    )

    args = arg_parser.parse_args()
    base_dir = os.path.abspath(args.base_dir)

    if not os.path.isdir(base_dir):
        print(f"Error: Directory not found: {base_dir}")
        sys.exit(1)

    if args.watch:
        run_watch(base_dir, args.interval)
    else:
        success = run_oneshot(base_dir)
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
