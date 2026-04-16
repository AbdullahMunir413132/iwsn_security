#!/usr/bin/env python3
"""
IWSN Security — Grafana Metrics Exporter v2.0

Reads the output from dpi_mqtt_analyzer (text reports) and exports metrics
in Prometheus exposition format for Grafana scraping, plus writes InfluxDB
line protocol for direct database push.

Three export modes:
  1. Prometheus text file: /tmp/iwsn_metrics.prom (node_exporter textfile collector)
  2. InfluxDB line protocol push (optional, if InfluxDB is configured)
  3. JSON metrics file for dashboard consumption

Usage:
  # After running dpi_mqtt_analyzer, export metrics:
  python3 grafana_exporter.py --report-dir ./reports

  # Continuous mode (re-export every N seconds):
  python3 grafana_exporter.py --report-dir ./reports --watch 10
"""

import os, sys, re, json, time, argparse
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

# ────────────────── REPORT PARSERS ──────────────────

def parse_ids_report(filepath):
    """Parse ids_detailed_report.txt → structured attack data."""
    if not os.path.exists(filepath):
        return {"attacks": [], "total": 0, "blocked_ips": 0}

    with open(filepath) as f:
        text = f.read()

    attacks = []
    # Parse individual attack records
    records = re.split(r"─{10,}", text)
    for rec in records:
        m_type = re.search(r"Attack Type:\s+(.+)", rec)
        m_sev = re.search(r"Severity:\s+(\w+)", rec)
        m_conf = re.search(r"Confidence:\s+([\d.]+)", rec)
        m_src = re.search(r"Source IP:\s+([\d.]+)", rec)
        m_dst = re.search(r"Target IP:\s+([\d.]+)", rec)
        m_pkts = re.search(r"Packets:\s+(\d+)", rec)
        m_pps = re.search(r"Rate:\s+([\d.]+)\s+pkt/s", rec)
        if m_type:
            attacks.append({
                "type": m_type.group(1).strip(),
                "severity": m_sev.group(1).strip() if m_sev else "UNKNOWN",
                "confidence": float(m_conf.group(1)) if m_conf else 0.0,
                "src_ip": m_src.group(1) if m_src else "",
                "dst_ip": m_dst.group(1) if m_dst else "",
                "packets": int(m_pkts.group(1)) if m_pkts else 0,
                "pps": float(m_pps.group(1)) if m_pps else 0.0,
            })

    m_total = re.search(r"Total Attacks Detected:\s+(\d+)", text)
    m_blocked = re.search(r"Blocked (\d+) attacker IPs", text)

    return {
        "attacks": attacks,
        "total": int(m_total.group(1)) if m_total else len(attacks),
        "blocked_ips": int(m_blocked.group(1)) if m_blocked else 0,
    }

def parse_performance_metrics(filepath):
    """Parse performance_metrics.txt → throughput, timing, accuracy data."""
    if not os.path.exists(filepath):
        return {}

    with open(filepath) as f:
        text = f.read()

    metrics = {}
    patterns = {
        "total_packets": r"Total Packets.*?:\s+(\d+)",
        "total_flows": r"Total [Ff]lows:\s+(\d+)",
        "total_bytes": r"Total Bytes:\s+(\d+)",
        "dpi_time_ms": r"DPI.*?Time.*?:\s+([\d.]+)\s*ms",
        "ids_time_ms": r"IDS.*?Time.*?:\s+([\d.]+)\s*ms",
        "mqtt_time_ms": r"MQTT.*?Time.*?:\s+([\d.]+)\s*ms",
        "throughput_pps": r"Throughput.*?:\s+([\d,.]+)\s*pkt",
        "throughput_mbps": r"Throughput.*?:\s+([\d.]+)\s*Mbps",
        "true_positives": r"True Positives.*?:\s+(\d+)",
        "false_positives": r"False Positives.*?:\s+(\d+)",
        "true_negatives": r"True Negatives.*?:\s+(\d+)",
        "false_negatives": r"False Negatives.*?:\s+(\d+)",
        "precision": r"Precision.*?:\s+([\d.]+)",
        "recall": r"Recall.*?:\s+([\d.]+)",
        "f1_score": r"F1.*?:\s+([\d.]+)",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            val = m.group(1).replace(",", "")
            try:
                metrics[key] = int(val)
            except ValueError:
                metrics[key] = float(val)

    return metrics

def parse_mqtt_report(filepath):
    """Parse mqtt_packets_detailed.txt → MQTT flow/message counts."""
    if not os.path.exists(filepath):
        return {"flows": 0, "messages": 0, "topics": []}

    with open(filepath) as f:
        text = f.read()

    flows = len(re.findall(r"MQTT Flow", text, re.IGNORECASE))
    messages = len(re.findall(r"Type:\s+PUBLISH", text, re.IGNORECASE))
    topics = list(set(re.findall(r"Topic:\s+(.+)", text)))

    return {"flows": flows, "messages": messages, "topics": topics}

def parse_dpi_report(filepath):
    """Parse dpi_detailed_report.txt → protocol distribution."""
    if not os.path.exists(filepath):
        return {"protocols": {}}

    with open(filepath) as f:
        text = f.read()

    protocols = {}
    for m in re.finditer(r"Protocol:\s+(\S+)", text):
        proto = m.group(1)
        protocols[proto] = protocols.get(proto, 0) + 1

    return {"protocols": protocols}

# ────────────────── EXPORTERS ──────────────────

def export_prometheus(ids_data, perf_data, mqtt_data, output_path):
    """Write Prometheus exposition format metrics file."""
    lines = []
    ts = int(time.time() * 1000)

    # IDS metrics
    lines.append("# HELP iwsn_attacks_total Total attacks detected")
    lines.append("# TYPE iwsn_attacks_total gauge")
    lines.append(f'iwsn_attacks_total {ids_data["total"]}')

    lines.append("# HELP iwsn_blocked_ips Number of blocked attacker IPs")
    lines.append("# TYPE iwsn_blocked_ips gauge")
    lines.append(f'iwsn_blocked_ips {ids_data["blocked_ips"]}')

    # Per-attack-type counts
    type_counts = {}
    for atk in ids_data["attacks"]:
        t = atk["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    lines.append("# HELP iwsn_attack_by_type Attack count by type")
    lines.append("# TYPE iwsn_attack_by_type gauge")
    for atype, count in type_counts.items():
        safe_type = atype.replace('"', '\\"')
        lines.append(f'iwsn_attack_by_type{{type="{safe_type}"}} {count}')

    # Performance metrics
    for key in ["total_packets", "total_flows", "throughput_pps"]:
        if key in perf_data:
            lines.append(f"# HELP iwsn_{key} {key.replace('_', ' ')}")
            lines.append(f"# TYPE iwsn_{key} gauge")
            lines.append(f"iwsn_{key} {perf_data[key]}")

    for key in ["dpi_time_ms", "ids_time_ms", "mqtt_time_ms"]:
        if key in perf_data:
            lines.append(f"# HELP iwsn_{key} {key.replace('_', ' ')}")
            lines.append(f"# TYPE iwsn_{key} gauge")
            lines.append(f"iwsn_{key} {perf_data[key]}")

    # Accuracy
    for key in ["precision", "recall", "f1_score"]:
        if key in perf_data:
            lines.append(f"# HELP iwsn_{key} IDS {key.replace('_', ' ')}")
            lines.append(f"# TYPE iwsn_{key} gauge")
            lines.append(f"iwsn_{key} {perf_data[key]}")

    # MQTT metrics
    lines.append("# HELP iwsn_mqtt_flows MQTT flows detected")
    lines.append("# TYPE iwsn_mqtt_flows gauge")
    lines.append(f'iwsn_mqtt_flows {mqtt_data["flows"]}')

    lines.append("# HELP iwsn_mqtt_messages MQTT messages parsed")
    lines.append("# TYPE iwsn_mqtt_messages gauge")
    lines.append(f'iwsn_mqtt_messages {mqtt_data["messages"]}')

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return output_path


def export_json_metrics(ids_data, perf_data, mqtt_data, dpi_data, output_path):
    """Write consolidated JSON metrics for dashboard consumption."""
    metrics = {
        "timestamp": datetime.now().isoformat(),
        "ids": {
            "total_attacks": ids_data["total"],
            "blocked_ips": ids_data["blocked_ips"],
            "attacks": ids_data["attacks"],
        },
        "performance": perf_data,
        "mqtt": mqtt_data,
        "dpi": dpi_data,
    }

    with open(output_path, "w") as f:
        json.dump(metrics, f, indent=2)

    return output_path


def export_influxdb_lines(ids_data, perf_data, mqtt_data, output_path):
    """Write InfluxDB line protocol file for bulk import."""
    ts = int(time.time() * 1e9)  # nanoseconds
    lines = []

    # IDS summary
    lines.append(f"iwsn_ids total_attacks={ids_data['total']}i,blocked_ips={ids_data['blocked_ips']}i {ts}")

    # Per-attack entries
    for atk in ids_data["attacks"]:
        safe_type = atk["type"].replace(" ", "\\ ").replace(",", "\\,")
        lines.append(
            f"iwsn_attack,type={safe_type} "
            f"confidence={atk['confidence']},packets={atk['packets']}i,pps={atk['pps']} {ts}"
        )

    # Performance
    perf_fields = []
    for k, v in perf_data.items():
        if isinstance(v, int):
            perf_fields.append(f"{k}={v}i")
        elif isinstance(v, float):
            perf_fields.append(f"{k}={v}")
    if perf_fields:
        lines.append(f"iwsn_performance {','.join(perf_fields)} {ts}")

    # MQTT
    lines.append(f"iwsn_mqtt flows={mqtt_data['flows']}i,messages={mqtt_data['messages']}i {ts}")

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return output_path


# ────────────────── MAIN ──────────────────

def main():
    parser = argparse.ArgumentParser(description="IWSN Grafana Metrics Exporter v2.0")
    parser.add_argument("--report-dir", required=True, help="Directory containing report files from dpi_mqtt_analyzer")
    parser.add_argument("--output-dir", default=None, help="Output directory for exported metrics (default: same as report-dir)")
    parser.add_argument("--prom-output", default="/tmp/iwsn_metrics.prom", help="Prometheus textfile collector output")
    parser.add_argument("--watch", type=int, default=0, help="Re-export every N seconds (0 = one-shot)")
    args = parser.parse_args()

    report_dir = args.report_dir
    output_dir = args.output_dir or report_dir

    while True:
        # Parse all reports
        ids_data = parse_ids_report(os.path.join(report_dir, "ids_detailed_report.txt"))
        perf_data = parse_performance_metrics(os.path.join(report_dir, "performance_metrics.txt"))
        mqtt_data = parse_mqtt_report(os.path.join(report_dir, "mqtt_packets_detailed.txt"))
        dpi_data = parse_dpi_report(os.path.join(report_dir, "dpi_detailed_report.txt"))

        # Export
        prom_path = export_prometheus(ids_data, perf_data, mqtt_data, args.prom_output)
        json_path = export_json_metrics(ids_data, perf_data, mqtt_data, dpi_data,
                                        os.path.join(output_dir, "iwsn_metrics.json"))
        influx_path = export_influxdb_lines(ids_data, perf_data, mqtt_data,
                                            os.path.join(output_dir, "iwsn_metrics.influx"))

        now = datetime.now().strftime("%H:%M:%S")
        print(f"  [{now}] Exported: {prom_path}, {json_path}, {influx_path}")
        print(f"           Attacks: {ids_data['total']}, MQTT flows: {mqtt_data['flows']}, "
              f"Packets: {perf_data.get('total_packets', '?')}")

        if args.watch <= 0:
            break
        time.sleep(args.watch)


if __name__ == "__main__":
    main()
