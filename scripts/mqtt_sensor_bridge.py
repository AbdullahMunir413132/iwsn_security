#!/usr/bin/env python3
"""
IWSN Security — MQTT Sensor Bridge v1.0
========================================
Subscribes to the Mosquitto broker (plaintext or TLS-authenticated),
extracts sensor values from each ESP32 MQTT PUBLISH payload, and
writes them to InfluxDB so Grafana can display live sensor readings.

This is the correct way to extract sensor values from TLS-protected
MQTT: Mosquitto decrypts the stream for us before delivery, so we
receive plaintext JSON regardless of transport security.

Topics handled:
  iwsn/sensors/ultrasonic/distance  → distance_cm, status, alert
  iwsn/sensors/ir/obstacle          → obstacle_detected (0/1), raw_value
  iwsn/sensors/combined/reading     → distance_cm, obstacle_detected, alert_level
  iwsn/sensors/status/heartbeat     → wifi_rssi, uptime_seconds, free_heap
  iwsn/+/+/+  (any other)           → generic numeric fields forwarded as-is

Usage — plaintext (default port 1883):
  python3 mqtt_sensor_bridge.py
  python3 mqtt_sensor_bridge.py --broker 192.168.1.20

Usage — TLS (port 8883):
  python3 mqtt_sensor_bridge.py --tls --port 8883 --ca-cert /etc/mosquitto/ca.crt
  python3 mqtt_sensor_bridge.py --tls --port 8883 \\
      --ca-cert ca.crt --client-cert client.crt --client-key client.key

Usage — with username/password authentication:
  python3 mqtt_sensor_bridge.py --username iwsn_node --password secret
  # Or via environment variables (preferred for security):
  MQTT_USERNAME=iwsn_node MQTT_PASSWORD=secret python3 mqtt_sensor_bridge.py

InfluxDB target can be overridden:
  python3 mqtt_sensor_bridge.py --influx-url http://localhost:8086 \\
      --influx-token mytoken --influx-org myorg --influx-bucket mybucket
"""

import argparse
import json
import os
import re
import socket
import sys
import time
import signal
from datetime import datetime

# ── dependency checks ─────────────────────────────────────────────────────────
try:
    import paho.mqtt.client as mqtt_client
    import paho.mqtt.enums as mqtt_enums
    _PAHO_V2 = hasattr(mqtt_enums, 'CallbackAPIVersion')
except ImportError:
    print("[ERROR] paho-mqtt not installed.")
    print("        Install: pip install paho-mqtt")
    sys.exit(1)

try:
    from influxdb_client import InfluxDBClient, WriteOptions
    from influxdb_client.client.write_api import SYNCHRONOUS
    from influxdb_client.domain.write_precision import WritePrecision
    from influxdb_client.client.write.point import Point
except ImportError:
    print("[ERROR] influxdb-client not installed.")
    print("        Install: pip install influxdb-client")
    sys.exit(1)

# ── defaults (match the rest of the project) ─────────────────────────────────
_INFLUX_URL    = os.getenv("INFLUXDB_URL",    "http://localhost:8086")
_INFLUX_TOKEN  = os.getenv("INFLUXDB_TOKEN",  "iwsn-security-influxdb-token")
_INFLUX_ORG    = os.getenv("INFLUXDB_ORG",    "iwsn")
_INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "iwsn_metrics")

_DEFAULT_BROKER = os.getenv("MQTT_BROKER", "localhost")
_DEFAULT_PORT   = 1883

# ── alert level numeric mapping ───────────────────────────────────────────────
_ALERT_LEVEL_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


# ═════════════════════════════════════════════════════════════════════════════
#  InfluxDB writer
# ═════════════════════════════════════════════════════════════════════════════

class InfluxWriter:
    def __init__(self, url: str, token: str, org: str, bucket: str):
        self.org    = org
        self.bucket = bucket
        self.client = InfluxDBClient(url=url, token=token, org=org)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        print(f"  [InfluxDB] Connected to {url}  bucket={bucket}")

    def write(self, points: list):
        if not points:
            return
        try:
            self.write_api.write(bucket=self.bucket, record=points)
        except Exception as exc:
            print(f"  [InfluxDB] Write error: {exc}")

    def close(self):
        self.client.close()


# ═════════════════════════════════════════════════════════════════════════════
#  Payload parsers — one per ESP32 topic
# ═════════════════════════════════════════════════════════════════════════════

def _node_id_from_topic(topic: str) -> str:
    """Extract a stable node identifier from topic or payload."""
    parts = topic.split("/")
    # If topic has >=5 parts use the first path component after 'iwsn'
    return parts[1] if len(parts) >= 2 else "unknown"


def parse_ultrasonic(topic: str, payload: dict, now: int) -> list:
    """
    iwsn/sensors/ultrasonic/distance
    {"sensor_id":"SR04M-2","type":"ultrasonic","distance_cm":45.32,
     "unit":"cm","reading_num":12,"status":"valid","timestamp":1234}
    """
    pts = []
    node_id = payload.get("sensor_id", "SR04M-2")

    dist = payload.get("distance_cm")
    if dist is not None:
        p = (Point("mqtt_sensor_values")
             .tag("topic", topic)
             .tag("sensor_type", "ultrasonic")
             .tag("node_id", node_id)
             .field("distance_cm", float(dist))
             .time(now, WritePrecision.S))
        pts.append(p)

    # Alert flag as integer (0/1) for threshold colouring in Grafana
    alert_val = 1 if payload.get("alert") else 0
    pts.append(
        Point("mqtt_sensor_values")
        .tag("topic", topic)
        .tag("sensor_type", "ultrasonic")
        .tag("node_id", node_id)
        .field("proximity_alert", alert_val)
        .time(now, WritePrecision.S)
    )

    # Status as a numeric code: valid=0, close_range=1, far_range=2, error=3
    _status_map = {"valid": 0, "close_range": 1, "far_range": 2, "error": 3}
    status_code = _status_map.get(payload.get("status", ""), 0)
    pts.append(
        Point("mqtt_sensor_values")
        .tag("topic", topic)
        .tag("sensor_type", "ultrasonic")
        .tag("node_id", node_id)
        .field("status_code", status_code)
        .time(now, WritePrecision.S)
    )
    return pts


def parse_ir_obstacle(topic: str, payload: dict, now: int) -> list:
    """
    iwsn/sensors/ir/obstacle
    {"sensor_id":"IR_OA_01","type":"ir_obstacle","obstacle_detected":true,
     "raw_value":0,"status":"active","reading_num":12,"timestamp":1234}
    """
    node_id = payload.get("sensor_id", "IR_OA_01")
    detected = 1 if payload.get("obstacle_detected") else 0
    raw     = int(payload.get("raw_value", 0))
    return [
        Point("mqtt_sensor_values")
        .tag("topic", topic)
        .tag("sensor_type", "ir_obstacle")
        .tag("node_id", node_id)
        .field("obstacle_detected", detected)
        .field("raw_value", raw)
        .time(now, WritePrecision.S)
    ]


def parse_combined(topic: str, payload: dict, now: int) -> list:
    """
    iwsn/sensors/combined/reading
    {"node_id":"esp32_iwsn_node_01","reading_num":12,"timestamp":1234,
     "distance_cm":45.32,"obstacle_detected":false,"alert":"NONE",
     "alert_level":"LOW"}
    """
    node_id = payload.get("node_id", "unknown")
    pts = []

    dist = payload.get("distance_cm")
    if dist is not None:
        pts.append(
            Point("mqtt_sensor_values")
            .tag("topic", topic)
            .tag("sensor_type", "combined")
            .tag("node_id", node_id)
            .field("distance_cm", float(dist))
            .time(now, WritePrecision.S)
        )

    obstacle = 1 if payload.get("obstacle_detected") else 0
    alert_num = _ALERT_LEVEL_MAP.get(payload.get("alert_level", "LOW"), 0)

    pts.append(
        Point("mqtt_sensor_values")
        .tag("topic", topic)
        .tag("sensor_type", "combined")
        .tag("node_id", node_id)
        .field("obstacle_detected", obstacle)
        .field("alert_level", alert_num)
        .time(now, WritePrecision.S)
    )
    return pts


def parse_heartbeat(topic: str, payload: dict, now: int) -> list:
    """
    iwsn/sensors/status/heartbeat
    {"node_id":"esp32_iwsn_node_01","type":"heartbeat",
     "uptime_seconds":600,"wifi_rssi":-58,"wifi_ssid":"...",
     "free_heap":180000,"messages_sent":300}
    """
    node_id = payload.get("node_id", "unknown")
    pts = []

    for field, key in [("wifi_rssi", "wifi_rssi"),
                       ("uptime_seconds", "uptime_seconds"),
                       ("free_heap", "free_heap"),
                       ("messages_sent", "messages_sent")]:
        val = payload.get(key)
        if val is not None:
            pts.append(
                Point("mqtt_sensor_values")
                .tag("topic", topic)
                .tag("sensor_type", "heartbeat")
                .tag("node_id", node_id)
                .field(field, float(val))
                .time(now, WritePrecision.S)
            )
    return pts


def parse_generic(topic: str, payload: dict, now: int) -> list:
    """Forward all top-level numeric values from unknown topics."""
    node_id = _node_id_from_topic(topic)
    pts = []
    for key, val in payload.items():
        if isinstance(val, (int, float)) and key not in ("timestamp", "reading_num"):
            pts.append(
                Point("mqtt_sensor_values")
                .tag("topic", topic)
                .tag("sensor_type", "generic")
                .tag("node_id", node_id)
                .field(key, float(val))
                .time(now, WritePrecision.S)
            )
    return pts


# topic → parser function
_TOPIC_PARSERS = {
    "iwsn/sensors/ultrasonic/distance": parse_ultrasonic,
    "iwsn/sensors/ir/obstacle":         parse_ir_obstacle,
    "iwsn/sensors/combined/reading":    parse_combined,
    "iwsn/sensors/status/heartbeat":    parse_heartbeat,
}


# ═════════════════════════════════════════════════════════════════════════════
#  PCAP report parser — reads mqtt_packets_detailed.txt from the C DPI engine
# ═════════════════════════════════════════════════════════════════════════════

def parse_mqtt_report_file(filepath: str) -> tuple:
    """
    Parse mqtt_packets_detailed.txt (written by dpi_mqtt_analyzer after a
    PCAP analysis run).  Returns a tuple:
      (packets, encrypted_count)
    where `packets` is a list of (topic: str, payload_str: str) tuples
    for every successfully-parsed MQTT PUBLISH message found, and
    `encrypted_count` is the number of port-8883 blocks whose MQTT
    header could not be decoded (TLS-encrypted transport).
    """
    packets = []
    encrypted_count = 0

    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except (FileNotFoundError, PermissionError):
        return packets, encrypted_count

    # Each packet block starts with the header line printed by mqtt_reports.c
    blocks = re.split(r"\u250c\u2500 MQTT Packet #\d+", content)

    for block in blocks[1:]:
        # ── Encrypted / unparseable block ─────────────────────────────────
        if "TCP payload present but MQTT parsing failed" in block:
            dir_m = re.search(
                r"Direction:\s+[\d.]+:(\d+)\s+\u2192\s+[\d.]+:(\d+)", block
            )
            if dir_m:
                ports = {int(dir_m.group(1)), int(dir_m.group(2))}
                if 8883 in ports:
                    encrypted_count += 1
            continue

        # ── Only PUBLISH packets carry sensor payloads ─────────────────────
        ptype_m = re.search(r"Packet Type:\s+(\w+)", block)
        if not ptype_m or ptype_m.group(1).strip() != "PUBLISH":
            continue

        topic_m = re.search(r"Topic:\s+(.+)", block)
        if not topic_m:
            continue
        topic = topic_m.group(1).strip()

        # ── Extract payload from the MQTT Payload box ──────────────────────
        # C engine writes:  fprintf(fp, "|  |  \"%s\"\n", payload);
        # We grab everything between the first and last " on that line so
        # embedded JSON quotes do not break the match.
        payload_sec_m = re.search(
            r"MQTT Payload \u2500+(.+?)\u2514\u2500", block, re.DOTALL
        )
        if not payload_sec_m:
            continue

        line_m = re.search(
            r"\u2502\s+\u2502\s+\"(.+)\"", payload_sec_m.group(1)
        )
        if not line_m:
            continue

        packets.append((topic, line_m.group(1)))

    return packets, encrypted_count


def run_pcap_mode(args):
    """
    One-shot mode: parse mqtt_packets_detailed.txt produced by dpi_mqtt_analyzer
    and push extracted sensor values to InfluxDB so Grafana shows them.
    """
    print()
    print("\u2554" + "\u2550" * 62 + "\u2557")
    print("\u2551  IWSN \u2014 MQTT Sensor Bridge v1.0  [PCAP mode]                  \u2551")
    print("\u255a" + "\u2550" * 62 + "\u255d")
    print()
    print(f"  Source:   {args.pcap_source}")
    print(f"  InfluxDB: {args.influx_url}  bucket={args.influx_bucket}")
    print()

    packets, encrypted_count = parse_mqtt_report_file(args.pcap_source)

    if encrypted_count > 0:
        print(
            f"  [PCAP] {encrypted_count} packet(s) on port 8883 skipped "
            f"(TLS-encrypted at transport layer; C engine cannot decrypt)"
        )
        print(
            f"         For TLS sensor values use live mode ("
            f"./bin/iwsn live) where Mosquitto decrypts for us."
        )

    if not packets:
        print("  [PCAP] No parseable MQTT PUBLISH payloads found.")
        return

    print(f"  [PCAP] {len(packets)} MQTT PUBLISH packet(s) to process")

    influx = InfluxWriter(
        url=args.influx_url,
        token=args.influx_token,
        org=args.influx_org,
        bucket=args.influx_bucket,
    )

    now     = int(time.time())
    ts_str  = datetime.now().strftime("%H:%M:%S")
    all_pts: list = []
    rate_counts: dict = {}

    for topic, payload_str in packets:
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            continue

        parser = _TOPIC_PARSERS.get(topic, parse_generic)
        pts    = parser(topic, payload, now)
        all_pts.extend(pts)
        _print_sensor_line(ts_str, topic, payload)
        rate_counts[topic] = rate_counts.get(topic, 0) + 1

    # Session-rate summary (one entry per topic + overall)
    total = sum(rate_counts.values())
    for topic, count in rate_counts.items():
        all_pts.append(
            Point("mqtt_session_metrics")
            .tag("topic", topic)
            .field("messages_per_sec", float(count))
            .field("message_count",   count)
            .time(now, WritePrecision.S)
        )
    if total:
        all_pts.append(
            Point("mqtt_session_metrics")
            .tag("topic", "ALL")
            .field("messages_per_sec", float(total))
            .field("message_count",   total)
            .time(now, WritePrecision.S)
        )

    if all_pts:
        influx.write(all_pts)
        print(f"  [PCAP] Pushed {len(all_pts)} data point(s) to InfluxDB")
        print(f"         Dashboard: http://localhost:3000")
    else:
        print("  [PCAP] No sensor data to push "
              "(payloads may not match known ESP32 topic schemas)")

    influx.close()


# ═════════════════════════════════════════════════════════════════════════════
#  Session-rate tracker — writes msg/s per topic to InfluxDB
# ═════════════════════════════════════════════════════════════════════════════

class RateTracker:
    """Counts messages per topic and flushes msg/s metrics every 5 seconds."""
    def __init__(self, writer: InfluxWriter, flush_interval: float = 5.0):
        self._writer   = writer
        self._interval = flush_interval
        self._counts: dict[str, int] = {}
        self._total    = 0
        self._last_flush = time.monotonic()

    def record(self, topic: str):
        self._counts[topic] = self._counts.get(topic, 0) + 1
        self._total += 1
        if time.monotonic() - self._last_flush >= self._interval:
            self._flush()

    def _flush(self):
        elapsed = max(time.monotonic() - self._last_flush, 1e-6)
        now = int(time.time())
        pts = []
        for topic, count in self._counts.items():
            pts.append(
                Point("mqtt_session_metrics")
                .tag("topic", topic)
                .field("messages_per_sec", round(count / elapsed, 3))
                .field("message_count",   count)
                .time(now, WritePrecision.S)
            )
        # Overall rate
        pts.append(
            Point("mqtt_session_metrics")
            .tag("topic", "ALL")
            .field("messages_per_sec", round(self._total / elapsed, 3))
            .field("message_count",   self._total)
            .time(now, WritePrecision.S)
        )
        self._writer.write(pts)
        self._counts.clear()
        self._total = 0
        self._last_flush = time.monotonic()

    def final_flush(self):
        if self._total > 0:
            self._flush()


# ═════════════════════════════════════════════════════════════════════════════
#  MQTT bridge
# ═════════════════════════════════════════════════════════════════════════════

def build_client(args) -> mqtt_client.Client:
    """Create and configure a Paho MQTT client (v1 API, compatible with v2)."""
    client_id = f"iwsn_sensor_bridge_{int(time.time())}"

    if _PAHO_V2:
        client = mqtt_client.Client(
            callback_api_version=mqtt_enums.CallbackAPIVersion.VERSION1,
            client_id=client_id,
            clean_session=True,
        )
    else:
        client = mqtt_client.Client(client_id=client_id, clean_session=True)

    # Username / password auth (plaintext or TLS)
    username = args.username or os.getenv("MQTT_USERNAME")
    password = args.password or os.getenv("MQTT_PASSWORD")
    if username:
        client.username_pw_set(username, password)

    # TLS configuration
    if args.tls:
        import ssl
        # ca_cert required; client cert+key optional (mutual TLS)
        client.tls_set(
            ca_certs   = args.ca_cert or None,
            certfile   = args.client_cert or None,
            keyfile    = args.client_key or None,
            tls_version= ssl.PROTOCOL_TLS_CLIENT,
        )
        # Allow self-signed certs on the broker side when no ca_cert given
        if not args.ca_cert:
            client.tls_insecure_set(True)

    return client


def run_bridge(args):
    influx = InfluxWriter(
        url    = args.influx_url,
        token  = args.influx_token,
        org    = args.influx_org,
        bucket = args.influx_bucket,
    )
    rate_tracker = RateTracker(influx, flush_interval=5.0)

    # ── Paho callbacks ────────────────────────────────────────────────────────

    def on_connect(client, userdata, flags, rc):
        rc_messages = {
            0: "Connected",
            1: "Bad protocol version",
            2: "Client ID rejected",
            3: "Broker unavailable",
            4: "Bad credentials",
            5: "Not authorised",
        }
        if rc == 0:
            print(f"  [MQTT] Connected to {args.broker}:{args.port}"
                  f"{'  (TLS)' if args.tls else ''}")
            client.subscribe("iwsn/#", qos=1)
            print(f"  [MQTT] Subscribed to iwsn/#")
        else:
            print(f"  [MQTT] Connection refused: {rc_messages.get(rc, f'rc={rc}')}")

    def on_disconnect(client, userdata, rc):
        if rc != 0:
            print(f"  [MQTT] Unexpected disconnect (rc={rc}), will reconnect...")

    def on_message(client, userdata, msg):
        topic       = msg.topic
        payload_raw = msg.payload

        # Decode payload
        try:
            payload_str = payload_raw.decode("utf-8", errors="replace")
        except Exception:
            return

        # Parse JSON
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            # Non-JSON MQTT message — skip sensor extraction but track rate
            rate_tracker.record(topic)
            return

        now = int(time.time())
        ts  = datetime.now().strftime("%H:%M:%S")

        # Dispatch to the right parser
        parser = _TOPIC_PARSERS.get(topic, parse_generic)
        points = parser(topic, payload, now)

        if points:
            influx.write(points)
            # Print a compact status line
            _print_sensor_line(ts, topic, payload)

        rate_tracker.record(topic)

    # ── build and connect client ──────────────────────────────────────────────
    client = build_client(args)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    # Reconnect automatically on network drops
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    try:
        client.connect(args.broker, args.port, keepalive=60)
    except Exception as exc:
        print(f"  [ERROR] Cannot connect to broker {args.broker}:{args.port}: {exc}")
        print(f"          Make sure Mosquitto is running:")
        print(f"            sudo systemctl start mosquitto")
        influx.close()
        sys.exit(1)

    print(f"  [Bridge] Running — press Ctrl+C to stop")
    print(f"  [Bridge] Writing to InfluxDB measurement: mqtt_sensor_values")
    print()

    # Graceful shutdown
    def _shutdown(sig, frame):
        print(f"\n  [Bridge] Shutting down...")
        rate_tracker.final_flush()
        client.disconnect()
        influx.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    client.loop_forever()


# ═════════════════════════════════════════════════════════════════════════════
#  Pretty terminal output
# ═════════════════════════════════════════════════════════════════════════════

_TOPIC_LABELS = {
    "iwsn/sensors/ultrasonic/distance": ("📏", "Ultrasonic"),
    "iwsn/sensors/ir/obstacle":         ("🔴", "IR Obstacle"),
    "iwsn/sensors/combined/reading":    ("📊", "Combined  "),
    "iwsn/sensors/status/heartbeat":    ("💓", "Heartbeat "),
}

def _print_sensor_line(ts: str, topic: str, payload: dict):
    icon, label = _TOPIC_LABELS.get(topic, ("📦", "Sensor    "))

    if "distance_cm" in payload and payload["distance_cm"] is not None:
        detail = f"distance={payload['distance_cm']:.1f} cm"
    elif "obstacle_detected" in payload:
        val    = payload["obstacle_detected"]
        detail = f"obstacle={'YES ⛔' if val else 'NO  ✅'}"
    elif "wifi_rssi" in payload:
        detail = (f"rssi={payload.get('wifi_rssi')} dBm  "
                  f"uptime={payload.get('uptime_seconds')}s  "
                  f"heap={payload.get('free_heap')} B")
    elif "alert_level" in payload:
        detail = (f"dist={payload.get('distance_cm','?')} cm  "
                  f"alert={payload.get('alert_level','?')}")
    else:
        detail = str(payload)[:80]

    print(f"  [{ts}] {icon} {label}  {detail}  → InfluxDB")


# ═════════════════════════════════════════════════════════════════════════════
#  Auto-detect broker TLS
# ═════════════════════════════════════════════════════════════════════════════

def auto_detect_broker(args):
    """
    Probe the broker host for MQTT ports and mutate args.port / args.tls.
    Tries port 1883 (plaintext) first; falls back to 8883 (TLS).
    """
    def _reachable(host: str, port: int, timeout: float = 2.0) -> bool:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    print(f"  [AutoDetect] Probing {args.broker} for MQTT broker port...")

    if _reachable(args.broker, 1883):
        args.port = 1883
        args.tls  = False
        print("  [AutoDetect] Port 1883 open \u2192 plaintext MQTT")
    elif _reachable(args.broker, 8883):
        args.port = 8883
        args.tls  = True
        print("  [AutoDetect] Port 8883 open \u2192 TLS MQTT (insecure mode, no cert verify)")
    else:
        print(
            f"  [AutoDetect] Neither port 1883 nor 8883 reachable on {args.broker}.\n"
            f"               Is Mosquitto running?  sudo systemctl start mosquitto"
        )
        sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="IWSN MQTT Sensor Bridge — extracts sensor values and writes to InfluxDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── PCAP / one-shot mode ─────────────────────────────────────────────────
    pcap_grp = parser.add_argument_group(
        "PCAP mode (one-shot, no broker connection)"
    )
    pcap_grp.add_argument(
        "--pcap-source",
        default=None,
        metavar="FILE",
        help="Parse mqtt_packets_detailed.txt from a previous dpi_mqtt_analyzer run "
             "and push extracted sensor values to InfluxDB (one-shot, no broker connection).",
    )

    # ── MQTT connection ───────────────────────────────────────────────────────
    mqtt_grp = parser.add_argument_group("MQTT connection (live mode)")
    mqtt_grp.add_argument("--broker",  default=_DEFAULT_BROKER, help=f"Mosquitto hostname/IP (default: {_DEFAULT_BROKER})")
    mqtt_grp.add_argument("--port",    type=int, default=_DEFAULT_PORT, help=f"Broker port (default: {_DEFAULT_PORT})")
    mqtt_grp.add_argument(
        "--auto-detect-tls",
        action="store_true",
        help="Automatically probe the broker for port 1883 (plaintext) and fall back "
             "to port 8883 (TLS) if 1883 is unreachable.  Overrides --port and --tls.",
    )

    # ── TLS ───────────────────────────────────────────────────────────────────
    tls_grp = parser.add_argument_group("TLS (use --tls to enable)")
    tls_grp.add_argument("--tls",         action="store_true", help="Enable TLS transport (port 8883 by default)")
    tls_grp.add_argument("--ca-cert",     default=None, metavar="FILE", help="CA certificate file (PEM)")
    tls_grp.add_argument("--client-cert", default=None, metavar="FILE", help="Client certificate file (PEM) — for mutual TLS")
    tls_grp.add_argument("--client-key",  default=None, metavar="FILE", help="Client private key file (PEM) — for mutual TLS")

    # ── Auth ──────────────────────────────────────────────────────────────────
    auth_grp = parser.add_argument_group("Authentication (also via MQTT_USERNAME / MQTT_PASSWORD env vars)")
    auth_grp.add_argument("--username", default=None, help="MQTT username")
    auth_grp.add_argument("--password", default=None, help="MQTT password")

    # ── InfluxDB ──────────────────────────────────────────────────────────────
    influx_grp = parser.add_argument_group("InfluxDB target")
    influx_grp.add_argument("--influx-url",    default=_INFLUX_URL,    help=f"InfluxDB URL (default: {_INFLUX_URL})")
    influx_grp.add_argument("--influx-token",  default=_INFLUX_TOKEN,  help="InfluxDB token")
    influx_grp.add_argument("--influx-org",    default=_INFLUX_ORG,    help=f"InfluxDB org (default: {_INFLUX_ORG})")
    influx_grp.add_argument("--influx-bucket", default=_INFLUX_BUCKET, help=f"InfluxDB bucket (default: {_INFLUX_BUCKET})")

    args = parser.parse_args()

    # ── PCAP one-shot mode ────────────────────────────────────────────────────
    if args.pcap_source:
        run_pcap_mode(args)
        return

    # ── Live broker mode ──────────────────────────────────────────────────────
    if args.auto_detect_tls:
        auto_detect_broker(args)
    elif args.tls and args.port == _DEFAULT_PORT:
        # User said --tls but didn't set --port: default to 8883
        args.port = 8883
        print(f"  [TLS] Port auto-set to 8883")

    print()
    print("\u2554" + "\u2550" * 62 + "\u2557")
    print("\u2551  IWSN \u2014 MQTT Sensor Bridge v1.0                              \u2551")
    print("\u2551  Sensor values \u2192 InfluxDB \u2192 Grafana (real-time)             \u2551")
    print("\u255a" + "\u2550" * 62 + "\u255d")
    print()
    print(f"  Broker:    {args.broker}:{args.port}{'  [TLS]' if args.tls else ''}")
    print(f"  Auth:      {'username/password' if (args.username or os.getenv('MQTT_USERNAME')) else 'none (anonymous)'}")
    print(f"  InfluxDB:  {args.influx_url}  bucket={args.influx_bucket}")
    print()

    run_bridge(args)


if __name__ == "__main__":
    main()
