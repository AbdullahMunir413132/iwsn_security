#!/usr/bin/env python3
"""
IWSN Security — RFC-Compliant Attack Simulator v3.0
Generates synthetic PCAP files for all 21 attack types + MQTT sensor traffic
with ground truth manifest.

Usage:
  python3 attack_simulator.py --preset all          # Generate all 21 attacks + MQTT + normal
  python3 attack_simulator.py --preset syn_flood     # Single attack
  python3 attack_simulator.py --preset mqtt_traffic  # Just MQTT sensor traffic
  python3 attack_simulator.py --difficulty easy       # Set difficulty level
  python3 attack_simulator.py --list                  # List all presets
"""

import sys, os, json, time, argparse, random, struct

try:
    from scapy.all import (Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, NTP,
                           wrpcap, RandShort, RandIP, fragment)
except ImportError:
    print("[!] Scapy required. Install: pip3 install scapy")
    sys.exit(1)

# ────────────────────── CONFIGURATION ──────────────────────

DIFFICULTY_PROFILES = {
    "easy":    {"rate_mult": 2.0, "noise_pct": 0,   "desc": "Textbook attacks, obvious signatures"},
    "medium":  {"rate_mult": 1.0, "noise_pct": 20,  "desc": "Standard rates with some normal traffic"},
    "hard":    {"rate_mult": 0.5, "noise_pct": 50,  "desc": "Low-and-slow with heavy noise mixing"},
    "extreme": {"rate_mult": 0.3, "noise_pct": 70,  "desc": "Evasive, multi-vector, heavily camouflaged"},
}

DEFAULT_TARGET = "192.168.1.100"
DEFAULT_ATTACKER = "10.0.0.50"
MQTT_BROKER = "192.168.1.10"

# ────────────────────── MQTT HELPERS ──────────────────────

def build_mqtt_connect(client_id="iwsn_sensor_01"):
    """Build a raw MQTT CONNECT packet (v3.1.1)."""
    # Variable header: Protocol Name(6) + Level(1) + Flags(1) + KeepAlive(2)
    proto_name = b"\x00\x04MQTT"  # Protocol name
    proto_level = b"\x04"         # MQTT 3.1.1
    connect_flags = b"\x02"       # Clean session
    keep_alive = b"\x00\x3C"      # 60 seconds
    var_header = proto_name + proto_level + connect_flags + keep_alive
    # Payload: Client ID
    cid = client_id.encode()
    payload = struct.pack(">H", len(cid)) + cid
    remaining = var_header + payload
    # Fixed header: type=1 (CONNECT), remaining length
    pkt_type = 0x10
    rem_len = len(remaining)
    fixed = bytes([pkt_type, rem_len])
    return fixed + remaining

def build_mqtt_connack():
    """Build a raw MQTT CONNACK packet."""
    return b"\x20\x02\x00\x00"  # CONNACK, len=2, no session, accepted

def build_mqtt_publish(topic, payload_str, qos=0):
    """Build a raw MQTT PUBLISH packet."""
    topic_bytes = topic.encode()
    payload_bytes = payload_str.encode()
    var_header = struct.pack(">H", len(topic_bytes)) + topic_bytes
    if qos > 0:
        var_header += struct.pack(">H", random.randint(1, 65535))  # Packet ID
    remaining = var_header + payload_bytes
    flags = 0x30 | ((qos & 0x03) << 1)  # PUBLISH + QoS
    rem_len = len(remaining)
    fixed = bytes([flags, rem_len])
    return fixed + remaining

def build_mqtt_subscribe(topic, qos=0):
    """Build a raw MQTT SUBSCRIBE packet."""
    topic_bytes = topic.encode()
    pkt_id = struct.pack(">H", random.randint(1, 65535))
    topic_filter = struct.pack(">H", len(topic_bytes)) + topic_bytes + bytes([qos])
    remaining = pkt_id + topic_filter
    fixed = bytes([0x82, len(remaining)])  # SUBSCRIBE = 0x82
    return fixed + remaining

def build_mqtt_suback(pkt_id=1):
    """Build a raw MQTT SUBACK packet."""
    return b"\x90\x03" + struct.pack(">H", pkt_id) + b"\x00"

def build_mqtt_pingreq():
    """Build MQTT PINGREQ."""
    return b"\xC0\x00"

def build_mqtt_pingresp():
    """Build MQTT PINGRESP."""
    return b"\xD0\x00"

def build_mqtt_disconnect():
    """Build MQTT DISCONNECT."""
    return b"\xE0\x00"

# ────────────────────── NORMAL + MQTT TRAFFIC HELPERS ──────────────────────

IWSN_TOPICS = [
    "sensors/temperature/node1",
    "sensors/temperature/node2",
    "sensors/humidity/node1",
    "sensors/humidity/node2",
    "sensors/pressure/node1",
    "sensors/light/node1",
    "sensors/motion/node1",
    "sensors/battery/node1",
    "sensors/battery/node2",
    "actuators/valve/node1",
    "actuators/relay/node1",
    "network/status/gateway",
]

IWSN_SENSOR_READINGS = {
    "temperature": lambda: {"value": round(random.uniform(18.0, 35.0), 2), "unit": "C"},
    "humidity":    lambda: {"value": round(random.uniform(30.0, 90.0), 1), "unit": "%"},
    "pressure":    lambda: {"value": round(random.uniform(990.0, 1030.0), 1), "unit": "hPa"},
    "light":       lambda: {"value": random.randint(0, 1023), "unit": "lux"},
    "motion":      lambda: {"value": random.choice([0, 1]), "unit": "bool"},
    "battery":     lambda: {"value": round(random.uniform(2.8, 4.2), 2), "unit": "V"},
    "valve":       lambda: {"value": random.choice(["open", "closed"]), "unit": "state"},
    "relay":       lambda: {"value": random.choice([0, 1]), "unit": "bool"},
    "status":      lambda: {"value": "online", "uptime": random.randint(100, 86400), "unit": "s"},
}

def get_sensor_payload(topic):
    """Generate a realistic JSON payload for the given IWSN topic."""
    for stype, gen_fn in IWSN_SENSOR_READINGS.items():
        if stype in topic:
            reading = gen_fn()
            return json.dumps(reading)
    return json.dumps({"value": random.randint(0, 100), "unit": "raw"})

def gen_normal_packets(count=50):
    """Generate normal background traffic (HTTP, DNS, MQTT, ICMP)."""
    pkts = []
    for i in range(count):
        src = f"192.168.1.{random.randint(2,254)}"
        dst = f"192.168.1.{random.randint(2,254)}"
        r = random.random()
        if r < 0.25:
            # Normal Web Traffic
            pkts.append(Ether()/IP(src=src, dst=dst)/TCP(sport=RandShort(), dport=80, flags="S"))
        elif r < 0.45:
            # Normal DNS
            pkts.append(Ether()/IP(src=src, dst=dst)/UDP(sport=RandShort(), dport=53)/Raw(b"\x00\x01dns"))
        elif r < 0.80:
            # Normal MQTT PUBLISH (IWSN sensor data)
            topic = random.choice(IWSN_TOPICS)
            payload_str = get_sensor_payload(topic)
            mqtt_data = build_mqtt_publish(topic, payload_str)
            pkts.append(Ether()/IP(src=src, dst=MQTT_BROKER)/TCP(sport=RandShort(), dport=1883, flags="PA")/Raw(mqtt_data))
        else:
            pkts.append(Ether()/IP(src=src, dst=dst)/ICMP())
    return pkts

def mix_noise(attack_pkts, noise_pct):
    """Interleave normal traffic into attack packets."""
    if noise_pct <= 0:
        return attack_pkts
    noise_count = int(len(attack_pkts) * noise_pct / 100)
    noise = gen_normal_packets(noise_count)
    combined = attack_pkts + noise
    random.shuffle(combined)
    return combined

def spread_packet_times(pkts, duration_seconds, jitter=0.0):
    """Spread packet timestamps across a duration to satisfy time-window detectors."""
    if not pkts:
        return pkts
    start = time.time()
    count = len(pkts)
    step = duration_seconds / max(1, count - 1)
    for i, p in enumerate(pkts):
        delta = (random.uniform(-jitter, jitter) if jitter > 0 else 0.0)
        p.time = start + (i * step) + delta
    return pkts

def save_attack(pkts, name, output_dir, manifest, noise_pct, attack_type, rfc_ref, pkt_count):
    """Save PCAP and record in manifest."""
    pkts = mix_noise(pkts, noise_pct)
    filepath = os.path.join(output_dir, f"{name}.pcap")
    wrpcap(filepath, pkts)
    fsz = os.path.getsize(filepath)
    mqtt_count = sum(1 for p in pkts if p.haslayer(TCP) and (p[TCP].dport == 1883 or p[TCP].sport == 1883))
    manifest["attacks"].append({
        "name": name,
        "file": filepath,
        "attack_type": attack_type,
        "rfc_reference": rfc_ref,
        "attack_packets": pkt_count,
        "total_packets": len(pkts),
        "mqtt_packets": mqtt_count,
        "noise_packets": len(pkts) - pkt_count,
        "file_size_bytes": fsz,
        "expected_detection": attack_type != "None" and attack_type != "MQTT Traffic"
    })
    mqtt_info = f", {mqtt_count} MQTT" if mqtt_count > 0 else ""
    print(f"  ✓ {name}.pcap — {len(pkts)} pkts ({pkt_count} attack + {len(pkts)-pkt_count} noise{mqtt_info}), {fsz/1024:.1f} KB")

# ────────────────────── ATTACK GENERATORS ──────────────────────

def gen_syn_flood(n=2000, target=DEFAULT_TARGET):
    """RFC 4987: SYN flood — mass SYN without completing handshake."""
    pkts = []
    for i in range(n):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/TCP(sport=RandShort(), dport=443, flags="S", seq=i*1000))
    return pkts

def gen_udp_flood(n=3000, target=DEFAULT_TARGET):
    """RFC 768/4732: UDP volumetric flood."""
    pkts = []
    for i in range(n):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=RandShort(), dport=53)/Raw(b"A"*64))
    return pkts

def gen_icmp_flood(n=2000, target=DEFAULT_TARGET):
    """RFC 792/4732: ICMP echo request flood."""
    return [Ether()/IP(src=f"10.0.{i//256}.{i%256}", dst=target)/ICMP(type=8, id=i, seq=i) for i in range(n)]

def gen_http_flood(n=300, target=DEFAULT_TARGET):
    """RFC 9110: HTTP GET request flood."""
    pkts = []
    for i in range(n):
        src = f"10.0.{(i // 200) + 1}.{(i % 200) + 1}"
        sp = 1024 + (i % 60000)
        pkts.append(Ether()/IP(src=src, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(f"GET / HTTP/1.1\r\nHost: target\r\n\r\n".encode()))
    return pkts

def gen_ping_of_death(n=20, target=DEFAULT_TARGET):
    """RFC 791 §3.2: Oversized ICMP packets exceeding 65535 bytes."""
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/ICMP()/Raw(b"X"*65000) for _ in range(n)]

def gen_land_attack(n=10, target=DEFAULT_TARGET):
    """RFC 6274/CVE-1999-0016: src==dst IP and port."""
    return [Ether()/IP(src=target, dst=target)/TCP(sport=4444, dport=4444, flags="S") for _ in range(n)]

def gen_smurf(n=500, target=DEFAULT_TARGET):
    """BCP 38: ICMP echo to broadcast with spoofed source."""
    bcast = "192.168.1.255"
    return [Ether()/IP(src=target, dst=bcast)/ICMP(type=8, id=i) for i in range(n)]

def gen_fraggle(n=500, target=DEFAULT_TARGET):
    """RFC 6274: UDP to broadcast echo/chargen ports."""
    bcast = "192.168.1.255"
    pkts = []
    for i in range(n):
        port = 7 if i % 2 == 0 else 19
        pkts.append(Ether()/IP(src=target, dst=bcast)/UDP(sport=RandShort(), dport=port)/Raw(b"echo"))
    return pkts

def gen_teardrop(n=50, target=DEFAULT_TARGET):
    """RFC 791 §3.2: Overlapping IP fragments."""
    pkts = []
    for _ in range(n):
        p1 = IP(src=DEFAULT_ATTACKER, dst=target, proto=17, flags="MF", frag=0)/Raw(b"\x00")
        p2 = IP(src=DEFAULT_ATTACKER, dst=target, proto=17, flags="MF", frag=1)/Raw(b"\x00\x00")
        p3 = IP(src=DEFAULT_ATTACKER, dst=target, proto=17, frag=1)/Raw(b"\x00")
        pkts.append(Ether()/p1)
        pkts.append(Ether()/p2)
        pkts.append(Ether()/p3)
    return pkts

def gen_syn_scan(n=12, target=DEFAULT_TARGET):
    """RFC 793: SYN scan — SYN to many ports, RST on response."""
    pkts = []
    for port in range(1, n+1):
        pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=port, flags="S"))
        pkts.append(Ether()/IP(src=target, dst=DEFAULT_ATTACKER)/TCP(sport=port, dport=54321, flags="R"))
    return spread_packet_times(pkts, duration_seconds=20, jitter=0.02)

def gen_connect_scan(n=12, target=DEFAULT_TARGET):
    """RFC 793: Full TCP connect scan — complete handshake then RST."""
    pkts = []
    for port in range(1, n+1):
        pkts.extend([
            Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=port, flags="S"),
            Ether()/IP(src=target, dst=DEFAULT_ATTACKER)/TCP(sport=port, dport=54321, flags="SA"),
            Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=port, flags="A"),
            Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=port, flags="R"),
        ])
    return spread_packet_times(pkts, duration_seconds=24, jitter=0.02)

def gen_udp_scan(n=60, target=DEFAULT_TARGET):
    """RFC 768: UDP scan — small probes to many ports."""
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/UDP(sport=54321, dport=p)/Raw(b"pr") for p in range(1, n+1)]

def gen_xmas_scan(n=50, target=DEFAULT_TARGET):
    """RFC 793 §3.9: FIN+PSH+URG flags set."""
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=p, flags="FPU") for p in range(1, n+1)]

def gen_null_scan(n=50, target=DEFAULT_TARGET):
    """RFC 793 §3.9: No TCP flags set."""
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=p, flags=0) for p in range(1, n+1)]

def gen_fin_scan(n=50, target=DEFAULT_TARGET):
    """RFC 793 §3.9: Only FIN flag set."""
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=p, flags="F") for p in range(1, n+1)]

def gen_rudy(n=30, target=DEFAULT_TARGET):
    """RFC 9110: Slow POST — send body at <10 bytes/sec."""
    pkts = []
    sp = 12345
    pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="S"))
    pkts.append(Ether()/IP(src=target, dst=DEFAULT_ATTACKER)/TCP(sport=80, dport=sp, flags="SA"))
    pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="A"))
    post = "POST /form HTTP/1.1\r\nHost: target\r\nContent-Length: 300\r\n\r\n"
    pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(post.encode()))
    for i in range(n):
        pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(b"A"))
    return spread_packet_times(pkts, duration_seconds=240, jitter=0.1)

def gen_slowloris(n=20, target=DEFAULT_TARGET):
    """RFC 9110: Slow HTTP headers — keep sending partial headers."""
    pkts = []
    start = time.time()
    for conn in range(n):
        sp = 20000 + conn
        timeline = [0, 2, 30, 60, 90, 120]
        payloads = [
            ("S", b""),
            ("PA", b"GET / HTTP/1.1\r\n"),
            ("PA", b"Host: target\r\n"),
            ("PA", b"User-Agent: slow\r\n"),
            ("PA", b"X-a: 1\r\n"),
            ("PA", b"X-b: 1\r\n"),
        ]
        for idx, (flags, payload) in enumerate(payloads):
            pkt = Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags=flags)
            if payload:
                pkt = pkt/Raw(payload)
            pkt.time = start + timeline[idx] + (conn * 0.01)
            pkts.append(pkt)
    return pkts

def gen_dns_amplification(n=200, target=DEFAULT_TARGET):
    """RFC 5358: Large DNS responses from port 53."""
    pkts = []
    for i in range(n):
        src = f"8.8.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=53, dport=RandShort())/Raw(b"D"*600))
    return pkts

def gen_ntp_amplification(n=200, target=DEFAULT_TARGET):
    """CVE-2013-5211: Large NTP monlist responses from port 123."""
    pkts = []
    for i in range(n):
        src = f"132.163.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=123, dport=RandShort())/Raw(b"N"*500))
    return pkts

def gen_arp_spoofing(n=30, target=DEFAULT_TARGET):
    """RFC 826/5227: Multiple MACs for same IP."""
    pkts = []
    for i in range(n):
        mac = f"aa:bb:cc:dd:ee:{i:02x}"
        pkts.append(Ether(src=mac)/IP(src=DEFAULT_ATTACKER, dst=target)/UDP(sport=RandShort(), dport=9999)/Raw(b"arp-spoof-test"))
    return pkts

def gen_ip_spoofing(n=50, target=DEFAULT_TARGET):
    """BCP 38: Packets with impossible source addresses."""
    pkts = []
    bad_srcs = ["0.0.0.0", "255.255.255.255", "224.0.0.1", "127.0.0.1"]
    for i in range(n):
        src = bad_srcs[i % len(bad_srcs)]
        pkts.append(Ether()/IP(src=src, dst=target)/TCP(sport=RandShort(), dport=80, flags="S"))
    return pkts

# ────────────────── MQTT TRAFFIC GENERATOR ──────────────────

def gen_mqtt_traffic(n_sessions=5, msgs_per_session=20):
    """
    Generate realistic IWSN MQTT sensor traffic.
    Simulates multiple sensor nodes connecting, subscribing, publishing data,
    sending keepalives, and disconnecting — all through a broker.
    """
    pkts = []
    broker = MQTT_BROKER
    base_port = 40000
    
    for sess in range(n_sessions):
        sensor_ip = f"192.168.1.{20 + sess}"
        client_id = f"iwsn_sensor_{sess:02d}"
        sport = base_port + sess
        
        # --- CONNECT handshake ---
        connect_data = build_mqtt_connect(client_id)
        pkts.append(Ether()/IP(src=sensor_ip, dst=broker)/TCP(sport=sport, dport=1883, flags="PA")/Raw(connect_data))
        
        connack_data = build_mqtt_connack()
        pkts.append(Ether()/IP(src=broker, dst=sensor_ip)/TCP(sport=1883, dport=sport, flags="PA")/Raw(connack_data))
        
        # --- SUBSCRIBE to control topic ---
        sub_topic = f"actuators/cmd/node{sess}"
        sub_data = build_mqtt_subscribe(sub_topic)
        pkts.append(Ether()/IP(src=sensor_ip, dst=broker)/TCP(sport=sport, dport=1883, flags="PA")/Raw(sub_data))
        
        suback_data = build_mqtt_suback()
        pkts.append(Ether()/IP(src=broker, dst=sensor_ip)/TCP(sport=1883, dport=sport, flags="PA")/Raw(suback_data))
        
        # --- PUBLISH sensor data ---
        for m in range(msgs_per_session):
            topic = random.choice(IWSN_TOPICS)
            payload_str = get_sensor_payload(topic)
            pub_data = build_mqtt_publish(topic, payload_str)
            pkts.append(Ether()/IP(src=sensor_ip, dst=broker)/TCP(sport=sport, dport=1883, flags="PA")/Raw(pub_data))
            
            # Occasionally add a PINGREQ/PINGRESP keepalive
            if m % 7 == 0:
                pkts.append(Ether()/IP(src=sensor_ip, dst=broker)/TCP(sport=sport, dport=1883, flags="PA")/Raw(build_mqtt_pingreq()))
                pkts.append(Ether()/IP(src=broker, dst=sensor_ip)/TCP(sport=1883, dport=sport, flags="PA")/Raw(build_mqtt_pingresp()))
        
        # --- DISCONNECT ---
        disc_data = build_mqtt_disconnect()
        pkts.append(Ether()/IP(src=sensor_ip, dst=broker)/TCP(sport=sport, dport=1883, flags="PA")/Raw(disc_data))
    
    return pkts

def gen_normal_only(n=500):
    """Clean traffic for false positive testing (includes MQTT)."""
    return gen_normal_packets(n)

# ────────────────────── ATTACK REGISTRY ──────────────────────

ATTACK_REGISTRY = {
    "syn_flood":         {"gen": gen_syn_flood,         "rfc": "RFC 4987, RFC 793",            "type": "SYN Flood"},
    "udp_flood":         {"gen": gen_udp_flood,         "rfc": "RFC 768, RFC 4732",            "type": "UDP Flood"},
    "icmp_flood":        {"gen": gen_icmp_flood,        "rfc": "RFC 792, RFC 4732",            "type": "ICMP Flood"},
    "http_flood":        {"gen": gen_http_flood,        "rfc": "RFC 9110, RFC 4732",           "type": "HTTP Flood"},
    "ping_of_death":     {"gen": gen_ping_of_death,     "rfc": "RFC 791 S3.2, RFC 6274",       "type": "Ping of Death"},
    "land_attack":       {"gen": gen_land_attack,       "rfc": "RFC 6274, CVE-1999-0016",      "type": "Land Attack"},
    "smurf_attack":      {"gen": gen_smurf,             "rfc": "RFC 2827 (BCP 38)",            "type": "Smurf Attack"},
    "fraggle_attack":    {"gen": gen_fraggle,           "rfc": "RFC 768, RFC 6274",            "type": "Fraggle Attack"},
    "teardrop_attack":   {"gen": gen_teardrop,          "rfc": "RFC 791 S3.2, RFC 6274",       "type": "Teardrop Attack"},
    "tcp_syn_scan":      {"gen": gen_syn_scan,          "rfc": "RFC 793 S3.9",                 "type": "TCP SYN Scan"},
    "tcp_connect_scan":  {"gen": gen_connect_scan,      "rfc": "RFC 793",                      "type": "TCP Connect Scan"},
    "udp_scan":          {"gen": gen_udp_scan,          "rfc": "RFC 768",                      "type": "UDP Scan"},
    "xmas_scan":         {"gen": gen_xmas_scan,         "rfc": "RFC 793 S3.9",                 "type": "Xmas Tree Scan"},
    "null_scan":         {"gen": gen_null_scan,          "rfc": "RFC 793 S3.9",                 "type": "NULL Scan"},
    "fin_scan":          {"gen": gen_fin_scan,           "rfc": "RFC 793 S3.9",                 "type": "FIN Scan"},
    "rudy_attack":       {"gen": gen_rudy,              "rfc": "RFC 9110, OWASP",              "type": "RUDY (Slow POST)"},
    "slowloris":         {"gen": gen_slowloris,         "rfc": "RFC 9110, OWASP",              "type": "Slowloris"},
    "dns_amplification": {"gen": gen_dns_amplification, "rfc": "RFC 5358, RFC 5625",           "type": "DNS Amplification"},
    "ntp_amplification": {"gen": gen_ntp_amplification, "rfc": "RFC 5905, CVE-2013-5211",      "type": "NTP Amplification"},
    "arp_spoofing":      {"gen": gen_arp_spoofing,      "rfc": "RFC 826, RFC 5227",            "type": "ARP Spoofing"},
    "ip_spoofing":       {"gen": gen_ip_spoofing,       "rfc": "RFC 2827 (BCP 38)",            "type": "IP Spoofing"},
    "mqtt_traffic":      {"gen": gen_mqtt_traffic,      "rfc": "MQTT v3.1.1 (OASIS)",          "type": "MQTT Traffic"},
}

# ────────────────────── MAIN ──────────────────────

def main():
    parser = argparse.ArgumentParser(description="IWSN Attack Simulator v3.0")
    parser.add_argument("--preset", default="all", help="Attack name, 'mqtt_traffic', or 'all'")
    parser.add_argument("--difficulty", default="easy", choices=DIFFICULTY_PROFILES.keys())
    parser.add_argument("--output", default="./simulator_output", help="Output directory")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    parser.add_argument("--list", action="store_true", help="List available attacks")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.list:
        print("\n╔══════════════════════════════════════════════════════════╗")
        print("║    Available Presets (21 Attacks + MQTT + Normal)       ║")
        print("╚══════════════════════════════════════════════════════════╝\n")
        for name, info in ATTACK_REGISTRY.items():
            print(f"  {name:25s} — {info['type']:25s} [{info['rfc']}]")
        print(f"\n  {'normal_traffic':25s} — {'Clean IWSN Traffic (FP)':25s} [N/A]")
        return

    diff = DIFFICULTY_PROFILES[args.difficulty]
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                                                              ║")
    print("║     IWSN Security — Attack Simulator v3.0                    ║")
    print("║     21 Attacks + MQTT Sensor Traffic + Ground Truth          ║")
    print("║                                                              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"\n  Difficulty:  {args.difficulty.upper()} — {diff['desc']}")
    print(f"  Output:      {output_dir}")
    print(f"  Noise:       {diff['noise_pct']}% normal traffic injection\n")

    manifest = {
        "generator": "IWSN Attack Simulator v3.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "difficulty": args.difficulty,
        "noise_percentage": diff["noise_pct"],
        "attacks": []
    }

    attacks_to_run = ATTACK_REGISTRY.keys() if args.preset == "all" else [args.preset]

    print("═══════════════════════════════════════════════════════════════")
    print("  Generating PCAPs")
    print("═══════════════════════════════════════════════════════════════\n")

    for name in attacks_to_run:
        if name not in ATTACK_REGISTRY:
            print(f"  ✗ Unknown preset: {name}")
            continue
        info = ATTACK_REGISTRY[name]
        pkts = info["gen"]()
        attack_count = len(pkts)
        save_attack(pkts, name, output_dir, manifest, diff["noise_pct"], info["type"], info["rfc"], attack_count)

    # Always generate normal traffic for FP testing
    print("\n  --- Normal IWSN Traffic (False Positive Test) ---")
    normal_pkts = gen_normal_only(500)
    filepath = os.path.join(output_dir, "normal_traffic.pcap")
    wrpcap(filepath, normal_pkts)
    mqtt_count = sum(1 for p in normal_pkts if p.haslayer(TCP) and (p[TCP].dport == 1883 or p[TCP].sport == 1883))
    manifest["attacks"].append({
        "name": "normal_traffic", "file": filepath, "attack_type": "None",
        "rfc_reference": "N/A", "attack_packets": 0, "total_packets": len(normal_pkts),
        "mqtt_packets": mqtt_count,
        "noise_packets": len(normal_pkts), "file_size_bytes": os.path.getsize(filepath),
        "expected_detection": False
    })
    print(f"  ✓ normal_traffic.pcap — {len(normal_pkts)} pkts (clean, {mqtt_count} MQTT)")

    # Save manifest
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    total_mqtt = sum(e.get("mqtt_packets", 0) for e in manifest["attacks"])
    print(f"\n═══════════════════════════════════════════════════════════════")
    print(f"  ✓ Generated {len(manifest['attacks'])} PCAPs + manifest.json")
    print(f"  ✓ Total MQTT packets across all PCAPs: {total_mqtt}")
    print(f"  ✓ Manifest: {manifest_path}")
    print(f"═══════════════════════════════════════════════════════════════\n")

if __name__ == "__main__":
    main()
