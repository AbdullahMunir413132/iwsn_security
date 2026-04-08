#!/usr/bin/env python3
"""
Quick test: Simulate ESP32 sensor MQTT traffic and capture as PCAP.
This lets you test the entire pipeline without real hardware.
"""
import subprocess
import time
import json
import random
import signal
import sys
import os

BROKER = "localhost"
TOPICS = {
    "ultrasonic": "iwsn/sensors/ultrasonic/distance",
    "ir":         "iwsn/sensors/ir/obstacle",
    "heartbeat":  "iwsn/sensors/status/heartbeat",
    "combined":   "iwsn/sensors/combined/reading",
}

def pub(topic, payload):
    """Publish a message via mosquitto_pub."""
    msg = json.dumps(payload)
    subprocess.run(["mosquitto_pub", "-h", BROKER, "-t", topic, "-m", msg],
                   capture_output=True, timeout=5)

def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  IWSN — ESP32 Traffic Simulator (Pipeline Test)            ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Duration: {duration}s | Broker: {BROKER}")
    print(f"  Publishing sensor data every 2 seconds...\n")
    
    reading = 0
    start = time.time()
    
    try:
        while time.time() - start < duration:
            reading += 1
            
            # Ultrasonic distance
            dist = round(20 + random.random() * 280, 2)
            pub(TOPICS["ultrasonic"], {
                "sensor_id": "SR04M-2", "type": "ultrasonic",
                "distance_cm": dist, "unit": "cm",
                "status": "close_range" if dist < 20 else "valid",
                "reading_num": reading, "timestamp": int(time.time())
            })
            
            # IR obstacle
            obstacle = random.random() < 0.15
            pub(TOPICS["ir"], {
                "sensor_id": "IR_OA_01", "type": "ir_obstacle",
                "obstacle_detected": obstacle,
                "raw_value": 0 if obstacle else 1,
                "status": "active", "reading_num": reading,
                "timestamp": int(time.time())
            })
            
            # Combined reading
            alert = "NONE"
            level = "LOW"
            if dist < 15 and obstacle:
                alert, level = "PROXIMITY_WARNING", "HIGH"
            elif obstacle:
                alert, level = "OBSTACLE_DETECTED", "MEDIUM"
            
            pub(TOPICS["combined"], {
                "node_id": "esp32_iwsn_node_01", "reading_num": reading,
                "ultrasonic": {"distance_cm": dist, "status": "valid"},
                "ir_obstacle": {"detected": obstacle, "raw": 0 if obstacle else 1},
                "alert": alert, "alert_level": level,
                "timestamp": int(time.time())
            })
            
            # Heartbeat every 5th reading
            if reading % 5 == 0:
                pub(TOPICS["heartbeat"], {
                    "node_id": "esp32_iwsn_node_01", "type": "heartbeat",
                    "uptime_seconds": int(time.time() - start),
                    "wifi_rssi": -40 - random.randint(0, 25),
                    "free_heap": 200000 + random.randint(0, 50000),
                    "ip_address": "192.168.1.105",
                    "messages_sent": reading * 3,
                    "status": "online", "timestamp": int(time.time())
                })
            
            elapsed = int(time.time() - start)
            print(f"  📡 Reading #{reading:3d} | dist={dist:6.1f}cm | "
                  f"IR={'⛔' if obstacle else '✅'} | {elapsed}s/{duration}s")
            
            time.sleep(2)
    
    except KeyboardInterrupt:
        pass
    
    print(f"\n  ✅ Simulation complete: {reading} readings published")
    print(f"     Total MQTT messages: ~{reading * 3 + reading // 5}")

if __name__ == "__main__":
    main()
