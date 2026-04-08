#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════════════
  IWSN Security — Live MQTT Sensor Monitor & Logger v1.0
══════════════════════════════════════════════════════════════

Beautiful terminal dashboard showing real-time sensor data
from ESP32 hardware over MQTT.

Usage:
  python3 live_mqtt_monitor.py                    # Default broker (localhost)
  python3 live_mqtt_monitor.py --broker 192.168.1.20
  python3 live_mqtt_monitor.py --log              # Also log to CSV
  python3 live_mqtt_monitor.py --duration 300     # Run for 5 minutes
"""

import sys
import os
import json
import time
import signal
import argparse
import csv
from datetime import datetime
from collections import defaultdict

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("❌ paho-mqtt required. Install: pip3 install paho-mqtt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════
#  TERMINAL COLORS & STYLING
# ══════════════════════════════════════════════════════════════

class Style:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GREEN= "\033[42m"
    BG_BLUE = "\033[44m"
    BG_GREY = "\033[100m"

# Sensor type icons & colors
SENSOR_STYLES = {
    "ultrasonic": {"icon": "📏", "color": Style.BLUE,    "label": "ULTRASONIC"},
    "ir_obstacle": {"icon": "🔴", "color": Style.RED,     "label": "IR OBSTACLE"},
    "heartbeat":  {"icon": "💓", "color": Style.GREEN,   "label": "HEARTBEAT"},
    "combined":   {"icon": "📊", "color": Style.MAGENTA, "label": "COMBINED"},
    "status":     {"icon": "📡", "color": Style.CYAN,    "label": "STATUS"},
    "default":    {"icon": "📦", "color": Style.YELLOW,  "label": "UNKNOWN"},
}

# ══════════════════════════════════════════════════════════════
#  LIVE STATS TRACKER
# ══════════════════════════════════════════════════════════════

class SensorStats:
    def __init__(self):
        self.total_messages = 0
        self.messages_by_topic = defaultdict(int)
        self.messages_per_second = 0.0
        self.start_time = time.time()
        self.last_second_count = 0
        self.last_second_time = time.time()
        
        # Sensor-specific data
        self.last_distance = None
        self.min_distance = float('inf')
        self.max_distance = 0
        self.distance_readings = []
        
        self.last_obstacle = None
        self.obstacle_count = 0
        self.clear_count = 0
        
        self.last_heartbeat = None
        self.node_rssi = None
        self.node_uptime = None
        self.node_heap = None
        
        # Alert tracking
        self.alerts = []
        
    def update_rate(self):
        now = time.time()
        if now - self.last_second_time >= 1.0:
            self.messages_per_second = (self.total_messages - self.last_second_count) / (now - self.last_second_time)
            self.last_second_count = self.total_messages
            self.last_second_time = now

stats = SensorStats()

# ══════════════════════════════════════════════════════════════
#  DISPLAY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')

def print_banner():
    print(f"{Style.CYAN}{Style.BOLD}")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║                                                                  ║")
    print("║   🛡️  IWSN SECURITY — Live MQTT Sensor Monitor v1.0            ║")
    print("║       Real Hardware • Real Data • Real Security                  ║")
    print("║                                                                  ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET}")

def print_stats_bar():
    elapsed = time.time() - stats.start_time
    mins = int(elapsed) // 60
    secs = int(elapsed) % 60
    
    stats.update_rate()
    
    print(f"{Style.BG_GREY}{Style.WHITE}{Style.BOLD}")
    print(f"  ⏱  {mins:02d}:{secs:02d}  │  "
          f"📨 {stats.total_messages} msgs  │  "
          f"⚡ {stats.messages_per_second:.1f} msg/s  │  "
          f"📡 Topics: {len(stats.messages_by_topic)}  │  "
          f"⛔ Obstacles: {stats.obstacle_count}  │  "
          f"✅ Clear: {stats.clear_count}"
          f"{Style.RESET}")
    print()

def print_sensor_dashboard():
    print(f"{Style.BOLD}┌─────────────────────────────────────────────────────────────────┐{Style.RESET}")
    
    # Ultrasonic section
    if stats.last_distance is not None:
        dist = stats.last_distance
        bar_len = min(int(dist / 5), 30)  # Scale: 5cm per block, max 30 blocks
        bar = "█" * bar_len + "░" * (30 - bar_len)
        
        if dist < 15:
            dist_color = Style.RED
            status = "⚠️  VERY CLOSE"
        elif dist < 50:
            dist_color = Style.YELLOW
            status = "📐 CLOSE"
        elif dist < 200:
            dist_color = Style.GREEN
            status = "✅ NORMAL"
        else:
            dist_color = Style.BLUE
            status = "📏 FAR"
        
        print(f"{Style.BOLD}│ 📏 ULTRASONIC SENSOR (SR04M-2)                                  │{Style.RESET}")
        print(f"│   Distance: {dist_color}{Style.BOLD}{dist:7.1f} cm{Style.RESET}  [{bar}]  {status}")
        
        if stats.distance_readings:
            avg_dist = sum(stats.distance_readings[-20:]) / len(stats.distance_readings[-20:])
            print(f"│   Min: {stats.min_distance:.1f}cm  Max: {stats.max_distance:.1f}cm  Avg(20): {avg_dist:.1f}cm")
    else:
        print(f"{Style.BOLD}│ 📏 ULTRASONIC SENSOR (SR04M-2)                                  │{Style.RESET}")
        print(f"│   {Style.DIM}Waiting for data...{Style.RESET}")
    
    print(f"│{'─' * 65}│")
    
    # IR Obstacle section
    if stats.last_obstacle is not None:
        if stats.last_obstacle:
            print(f"{Style.BOLD}│ 🔴 IR OBSTACLE SENSOR                                           │{Style.RESET}")
            print(f"│   Status: {Style.RED}{Style.BOLD}⛔ OBSTACLE DETECTED{Style.RESET}   "
                  f"[Total detections: {stats.obstacle_count}]")
        else:
            print(f"{Style.BOLD}│ 🟢 IR OBSTACLE SENSOR                                           │{Style.RESET}")
            print(f"│   Status: {Style.GREEN}{Style.BOLD}✅ PATH CLEAR{Style.RESET}           "
                  f"[Total detections: {stats.obstacle_count}]")
    else:
        print(f"{Style.BOLD}│ 🔴 IR OBSTACLE SENSOR                                           │{Style.RESET}")
        print(f"│   {Style.DIM}Waiting for data...{Style.RESET}")
    
    print(f"│{'─' * 65}│")
    
    # Node health section
    if stats.node_rssi is not None:
        rssi = stats.node_rssi
        if rssi > -50:
            rssi_bar = "█████"
            rssi_label = "Excellent"
        elif rssi > -60:
            rssi_bar = "████░"
            rssi_label = "Good"
        elif rssi > -70:
            rssi_bar = "███░░"
            rssi_label = "Fair"
        else:
            rssi_bar = "██░░░"
            rssi_label = "Weak"
        
        uptime_str = ""
        if stats.node_uptime:
            m, s = divmod(stats.node_uptime, 60)
            h, m = divmod(m, 60)
            uptime_str = f"{int(h):02d}:{int(m):02d}:{int(s):02d}"
        
        print(f"{Style.BOLD}│ 💓 NODE HEALTH                                                   │{Style.RESET}")
        print(f"│   WiFi: [{rssi_bar}] {rssi} dBm ({rssi_label})  "
              f"Uptime: {uptime_str}  Heap: {stats.node_heap or '?'} bytes")
    
    print(f"{Style.BOLD}└─────────────────────────────────────────────────────────────────┘{Style.RESET}")
    print()

def print_message(topic, payload_str, parsed):
    """Print a single incoming message in a beautiful format."""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    # Determine sensor type from topic
    sensor_type = "default"
    for key in SENSOR_STYLES:
        if key in topic:
            sensor_type = key
            break
    
    style = SENSOR_STYLES[sensor_type]
    
    # Compact one-line display for live stream
    if sensor_type == "ultrasonic" and parsed:
        dist = parsed.get("distance_cm", "?")
        status = parsed.get("status", "?")
        print(f"  {Style.DIM}[{timestamp}]{Style.RESET} {style['icon']} "
              f"{style['color']}{Style.BOLD}{dist} cm{Style.RESET} "
              f"({status}) #{parsed.get('reading_num', '?')}")
              
    elif sensor_type == "ir_obstacle" and parsed:
        detected = parsed.get("obstacle_detected", False)
        indicator = f"{Style.RED}⛔ OBSTACLE{Style.RESET}" if detected else f"{Style.GREEN}✅ CLEAR{Style.RESET}"
        print(f"  {Style.DIM}[{timestamp}]{Style.RESET} {style['icon']} "
              f"{indicator} #{parsed.get('reading_num', '?')}")
              
    elif sensor_type == "heartbeat" and parsed:
        rssi = parsed.get("wifi_rssi", "?")
        uptime = parsed.get("uptime_seconds", "?")
        msgs = parsed.get("messages_sent", "?")
        print(f"  {Style.DIM}[{timestamp}]{Style.RESET} {style['icon']} "
              f"{Style.GREEN}Node alive{Style.RESET} | "
              f"RSSI:{rssi}dBm Up:{uptime}s Msgs:{msgs}")
              
    elif sensor_type == "combined" and parsed:
        alert = parsed.get("alert", "NONE")
        level = parsed.get("alert_level", "LOW")
        if level == "HIGH":
            print(f"  {Style.DIM}[{timestamp}]{Style.RESET} {style['icon']} "
                  f"{Style.BG_RED}{Style.WHITE}{Style.BOLD} ⚠️  {alert} {Style.RESET}")
        elif level == "MEDIUM":
            print(f"  {Style.DIM}[{timestamp}]{Style.RESET} {style['icon']} "
                  f"{Style.YELLOW}{alert}{Style.RESET}")
        else:
            print(f"  {Style.DIM}[{timestamp}]{Style.RESET} {style['icon']} "
                  f"{Style.DIM}{alert}{Style.RESET}")
    else:
        # Generic display
        short_payload = payload_str[:80] + "..." if len(payload_str) > 80 else payload_str
        print(f"  {Style.DIM}[{timestamp}]{Style.RESET} {style['icon']} "
              f"{style['color']}{topic}{Style.RESET} → {short_payload}")

# ══════════════════════════════════════════════════════════════
#  CSV LOGGER
# ══════════════════════════════════════════════════════════════

class CSVLogger:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'w', newline='')
        self.writer = csv.writer(self.file)
        self.writer.writerow([
            'timestamp', 'topic', 'sensor_type', 'distance_cm',
            'obstacle_detected', 'rssi', 'uptime_s', 'raw_payload'
        ])
        self.file.flush()
        
    def log(self, topic, parsed, raw):
        row = [
            datetime.now().isoformat(),
            topic,
            parsed.get('type', ''),
            parsed.get('distance_cm', ''),
            parsed.get('obstacle_detected', ''),
            parsed.get('wifi_rssi', ''),
            parsed.get('uptime_seconds', ''),
            raw[:200]
        ]
        self.writer.writerow(row)
        self.file.flush()
    
    def close(self):
        self.file.close()

# ══════════════════════════════════════════════════════════════
#  MQTT CALLBACKS
# ══════════════════════════════════════════════════════════════

csv_logger = None
display_mode = "stream"  # "stream" or "dashboard"

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"{Style.GREEN}{Style.BOLD}✅ Connected to MQTT Broker!{Style.RESET}")
        client.subscribe("iwsn/#", qos=0)
        print(f"{Style.CYAN}📡 Subscribed to: iwsn/#{Style.RESET}")
        print()
        print(f"{Style.BOLD}{'─' * 65}{Style.RESET}")
        print(f"{Style.BOLD}  LIVE SENSOR STREAM{Style.RESET}")
        print(f"{Style.BOLD}{'─' * 65}{Style.RESET}")
    else:
        print(f"{Style.RED}❌ Connection failed (rc={rc}){Style.RESET}")

def on_message(client, userdata, msg):
    global stats, csv_logger
    
    topic = msg.topic
    payload_str = msg.payload.decode('utf-8', errors='replace')
    
    # Parse JSON
    parsed = {}
    try:
        parsed = json.loads(payload_str)
    except json.JSONDecodeError:
        parsed = {"raw": payload_str}
    
    # Update statistics
    stats.total_messages += 1
    stats.messages_by_topic[topic] += 1
    
    # Update sensor-specific stats
    if "ultrasonic" in topic and "distance_cm" in parsed:
        dist = parsed["distance_cm"]
        if dist is not None and isinstance(dist, (int, float)):
            stats.last_distance = dist
            stats.distance_readings.append(dist)
            if len(stats.distance_readings) > 100:
                stats.distance_readings = stats.distance_readings[-100:]
            stats.min_distance = min(stats.min_distance, dist)
            stats.max_distance = max(stats.max_distance, dist)
    
    elif "ir" in topic and "obstacle" in topic:
        detected = parsed.get("obstacle_detected", False)
        stats.last_obstacle = detected
        if detected:
            stats.obstacle_count += 1
        else:
            stats.clear_count += 1
    
    elif "heartbeat" in topic:
        stats.last_heartbeat = time.time()
        stats.node_rssi = parsed.get("wifi_rssi")
        stats.node_uptime = parsed.get("uptime_seconds")
        stats.node_heap = parsed.get("free_heap")
    
    elif "combined" in topic:
        alert = parsed.get("alert", "NONE")
        if alert != "NONE":
            stats.alerts.append({
                "time": datetime.now().isoformat(),
                "alert": alert,
                "level": parsed.get("alert_level", "LOW")
            })
            if len(stats.alerts) > 50:
                stats.alerts = stats.alerts[-50:]
    
    # Display
    print_message(topic, payload_str, parsed)
    
    # Log to CSV
    if csv_logger:
        csv_logger.log(topic, parsed, payload_str)
    
    # Periodically show dashboard summary (every 20 messages)
    if stats.total_messages % 20 == 0:
        print()
        print_stats_bar()
        print_sensor_dashboard()
        print(f"{Style.BOLD}{'─' * 65}{Style.RESET}")

def on_disconnect(client, userdata, rc):
    print(f"\n{Style.YELLOW}⚠️  Disconnected from broker (rc={rc}){Style.RESET}")

# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

def main():
    global csv_logger
    
    parser = argparse.ArgumentParser(description="IWSN Live MQTT Monitor")
    parser.add_argument("--broker", default="localhost", help="MQTT broker address")
    parser.add_argument("--port", type=int, default=1883, help="MQTT broker port")
    parser.add_argument("--log", action="store_true", help="Log to CSV file")
    parser.add_argument("--duration", type=int, default=0, help="Run duration in seconds (0=infinite)")
    parser.add_argument("--csv-file", default=None, help="CSV output filename")
    args = parser.parse_args()
    
    # Setup CSV logger
    if args.log:
        csv_filename = args.csv_file or f"mqtt_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        csv_logger = CSVLogger(csv_filename)
        print(f"{Style.GREEN}📝 Logging to: {csv_filename}{Style.RESET}")
    
    # Print banner
    print_banner()
    
    print(f"{Style.BOLD}[CONNECTION]{Style.RESET}")
    print(f"  Broker: {args.broker}:{args.port}")
    print(f"  Topics: iwsn/#")
    if args.duration > 0:
        print(f"  Duration: {args.duration}s")
    print()
    
    # Setup MQTT client
    client = mqtt.Client(client_id=f"iwsn_monitor_{int(time.time())}")
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        print(f"\n\n{Style.CYAN}{'═' * 65}{Style.RESET}")
        print(f"{Style.BOLD}  📊 FINAL SESSION SUMMARY{Style.RESET}")
        print(f"{Style.CYAN}{'═' * 65}{Style.RESET}")
        
        elapsed = time.time() - stats.start_time
        mins = int(elapsed) // 60
        secs = int(elapsed) % 60
        
        print(f"  Duration:          {mins}m {secs}s")
        print(f"  Total Messages:    {stats.total_messages}")
        print(f"  Avg Rate:          {stats.total_messages/max(elapsed,1):.1f} msg/s")
        print(f"  Unique Topics:     {len(stats.messages_by_topic)}")
        print()
        
        if stats.distance_readings:
            print(f"  📏 Ultrasonic Stats:")
            print(f"     Readings: {len(stats.distance_readings)}")
            print(f"     Min:      {stats.min_distance:.1f} cm")
            print(f"     Max:      {stats.max_distance:.1f} cm")
            print(f"     Avg:      {sum(stats.distance_readings)/len(stats.distance_readings):.1f} cm")
            print()
        
        print(f"  🔴 IR Obstacle Stats:")
        print(f"     Obstacles: {stats.obstacle_count}")
        print(f"     Clear:     {stats.clear_count}")
        print()
        
        if stats.messages_by_topic:
            print(f"  📨 Messages by Topic:")
            for topic, count in sorted(stats.messages_by_topic.items(), key=lambda x: -x[1]):
                print(f"     {topic}: {count}")
        
        print(f"\n{Style.CYAN}{'═' * 65}{Style.RESET}")
        
        if csv_logger:
            csv_logger.close()
            print(f"  📝 CSV log saved: {csv_logger.filename}")
        
        print(f"\n{Style.GREEN}🛡️  IWSN Security Monitor — Session ended.{Style.RESET}\n")
        client.disconnect()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Connect
    try:
        client.connect(args.broker, args.port, 60)
    except Exception as e:
        print(f"{Style.RED}❌ Cannot connect to broker: {e}{Style.RESET}")
        print(f"{Style.YELLOW}   Make sure Mosquitto is running: sudo systemctl start mosquitto{Style.RESET}")
        sys.exit(1)
    
    # Run
    if args.duration > 0:
        client.loop_start()
        time.sleep(args.duration)
        signal_handler(None, None)
    else:
        print(f"{Style.YELLOW}Press Ctrl+C to stop and see summary{Style.RESET}")
        print()
        client.loop_forever()

if __name__ == "__main__":
    main()
