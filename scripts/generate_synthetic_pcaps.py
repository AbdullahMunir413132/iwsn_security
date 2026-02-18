#!/usr/bin/env python3
"""
IWSN Security - Synthetic PCAP Generator
Creates synthetic network traffic PCAP files for testing
Uses scapy library
"""

import sys
import os

try:
    from scapy.all import *
except ImportError:
    print("[!] Scapy not found. Install with: pip3 install scapy")
    print("    Or: sudo apt-get install python3-scapy")
    sys.exit(1)

def print_header():
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║                                                                ║")
    print("║      IWSN Security - Synthetic PCAP Generator (Python)         ║")
    print("║         Creates test traffic using Scapy library               ║")
    print("║                                                                ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print()

def create_normal_traffic(filename, packet_count=100):
    """Generate normal TCP/UDP/ICMP traffic"""
    print(f"[*] Generating normal traffic: {filename}")
    packets = []
    
    # Mix of TCP, UDP, ICMP
    for i in range(packet_count):
        if i % 3 == 0:
            # TCP traffic
            pkt = Ether()/IP(src="192.168.1.10", dst="192.168.1.20")/\
                  TCP(sport=1024+i, dport=80, flags="S")
        elif i % 3 == 1:
            # UDP traffic
            pkt = Ether()/IP(src="192.168.1.10", dst="192.168.1.20")/\
                  UDP(sport=1024+i, dport=53)/Raw(load="test data")
        else:
            # ICMP traffic
            pkt = Ether()/IP(src="192.168.1.10", dst="192.168.1.20")/ICMP()
        
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"    [✓] Created {len(packets)} packets")

def create_syn_flood(filename, packet_count=2000):
    """Generate SYN flood attack traffic"""
    print(f"[*] Generating SYN flood: {filename}")
    packets = []
    
    target_ip = "192.168.1.100"
    target_port = 80
    
    for i in range(packet_count):
        # Random source IP and port
        src_ip = f"10.0.{(i//256)%256}.{i%256}"
        src_port = 1024 + (i % 60000)
        
        pkt = Ether()/IP(src=src_ip, dst=target_ip)/\
              TCP(sport=src_port, dport=target_port, flags="S", seq=i*1000)
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"    [✓] Created {len(packets)} SYN packets")

def create_udp_flood(filename, packet_count=3000):
    """Generate UDP flood attack traffic"""
    print(f"[*] Generating UDP flood: {filename}")
    packets = []
    
    target_ip = "192.168.1.100"
    target_port = 53
    
    for i in range(packet_count):
        src_ip = f"10.0.{(i//256)%256}.{i%256}"
        src_port = 1024 + (i % 60000)
        
        pkt = Ether()/IP(src=src_ip, dst=target_ip)/\
              UDP(sport=src_port, dport=target_port)/\
              Raw(load=b"A"*64)
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"    [✓] Created {len(packets)} UDP packets")

def create_icmp_flood(filename, packet_count=2000):
    """Generate ICMP flood attack traffic"""
    print(f"[*] Generating ICMP flood: {filename}")
    packets = []
    
    target_ip = "192.168.1.100"
    
    for i in range(packet_count):
        src_ip = f"10.0.{(i//256)%256}.{i%256}"
        
        pkt = Ether()/IP(src=src_ip, dst=target_ip)/\
              ICMP(type=8, code=0, id=i, seq=i)
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"    [✓] Created {len(packets)} ICMP packets")

def create_ping_of_death(filename):
    """Generate Ping of Death (oversized ICMP)"""
    print(f"[*] Generating Ping of Death: {filename}")
    packets = []
    
    target_ip = "192.168.1.100"
    src_ip = "192.168.1.10"
    
    # Create oversized ICMP packets (will be fragmented)
    for i in range(20):
        # 65000+ byte payload
        pkt = Ether()/IP(src=src_ip, dst=target_ip)/\
              ICMP(type=8)/Raw(load=b"X"*65000)
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"    [✓] Created {len(packets)} oversized ICMP packets")

def create_port_scan_syn(filename, port_count=50):
    """Generate TCP SYN port scan"""
    print(f"[*] Generating TCP SYN scan: {filename}")
    packets = []
    
    scanner_ip = "192.168.1.10"
    target_ip = "192.168.1.100"
    src_port = 54321
    
    # Scan ports 1-port_count
    for port in range(1, port_count + 1):
        pkt = Ether()/IP(src=scanner_ip, dst=target_ip)/\
              TCP(sport=src_port, dport=port, flags="S", seq=port*1000)
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"    [✓] Created scan of {port_count} ports")

def create_port_scan_connect(filename, port_count=30):
    """Generate TCP Connect scan (full handshake)"""
    print(f"[*] Generating TCP Connect scan: {filename}")
    packets = []
    
    scanner_ip = "192.168.1.10"
    target_ip = "192.168.1.100"
    src_port = 54321
    
    for port in range(1, port_count + 1):
        # SYN
        pkt1 = Ether()/IP(src=scanner_ip, dst=target_ip)/\
               TCP(sport=src_port, dport=port, flags="S", seq=1000+port)
        # SYN-ACK (response)
        pkt2 = Ether()/IP(src=target_ip, dst=scanner_ip)/\
               TCP(sport=port, dport=src_port, flags="SA", seq=2000+port, ack=1001+port)
        # ACK
        pkt3 = Ether()/IP(src=scanner_ip, dst=target_ip)/\
               TCP(sport=src_port, dport=port, flags="A", seq=1001+port, ack=2001+port)
        # RST (close)
        pkt4 = Ether()/IP(src=scanner_ip, dst=target_ip)/\
               TCP(sport=src_port, dport=port, flags="R", seq=1001+port)
        
        packets.extend([pkt1, pkt2, pkt3, pkt4])
    
    wrpcap(filename, packets)
    print(f"    [✓] Created full connect scan of {port_count} ports")

def create_udp_scan(filename, port_count=40):
    """Generate UDP port scan"""
    print(f"[*] Generating UDP scan: {filename}")
    packets = []
    
    scanner_ip = "192.168.1.10"
    target_ip = "192.168.1.100"
    src_port = 54321
    
    for port in range(1, port_count + 1):
        # Small UDP probe packet
        pkt = Ether()/IP(src=scanner_ip, dst=target_ip)/\
              UDP(sport=src_port, dport=port)/Raw(load=b"probe")
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"    [✓] Created UDP scan of {port_count} ports")

def create_http_flood(filename, request_count=300):
    """Generate HTTP flood (GET requests)"""
    print(f"[*] Generating HTTP flood: {filename}")
    packets = []
    
    target_ip = "192.168.1.100"
    target_port = 80
    
    for i in range(request_count):
        src_ip = f"10.0.{(i//256)%256}.{i%256}"
        src_port = 1024 + (i % 60000)
        
        # TCP SYN
        syn = Ether()/IP(src=src_ip, dst=target_ip)/\
              TCP(sport=src_port, dport=target_port, flags="S", seq=1000+i)
        
        # TCP SYN-ACK
        synack = Ether()/IP(src=target_ip, dst=src_ip)/\
                 TCP(sport=target_port, dport=src_port, flags="SA", seq=2000+i, ack=1001+i)
        
        # TCP ACK
        ack = Ether()/IP(src=src_ip, dst=target_ip)/\
              TCP(sport=src_port, dport=target_port, flags="A", seq=1001+i, ack=2001+i)
        
        # HTTP GET request
        http_req = f"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: flood-{i}\r\n\r\n"
        http = Ether()/IP(src=src_ip, dst=target_ip)/\
               TCP(sport=src_port, dport=target_port, flags="PA", seq=1001+i, ack=2001+i)/\
               Raw(load=http_req)
        
        packets.extend([syn, synack, ack, http])
    
    wrpcap(filename, packets)
    print(f"    [✓] Created {request_count} HTTP requests")

def create_mqtt_traffic(filename, message_count=50):
    """Generate MQTT traffic"""
    print(f"[*] Generating MQTT traffic: {filename}")
    packets = []
    
    client_ip = "192.168.1.10"
    broker_ip = "192.168.1.20"
    mqtt_port = 1883
    client_port = 45678
    
    # MQTT CONNECT
    mqtt_connect = b"\x10\x1a\x00\x04MQTT\x04\x02\x00\x3c\x00\x0ctest_client"
    pkt = Ether()/IP(src=client_ip, dst=broker_ip)/\
          TCP(sport=client_port, dport=mqtt_port, flags="PA")/\
          Raw(load=mqtt_connect)
    packets.append(pkt)
    
    # MQTT PUBLISH messages
    for i in range(message_count):
        topic = f"sensor/{i}"
        payload = f"{{\"temp\":{20+i%10},\"hum\":{50+i%20}}}"
        
        # Simplified MQTT PUBLISH packet
        mqtt_pub = b"\x30" + bytes([len(topic) + len(payload) + 2]) + \
                   bytes([0, len(topic)]) + topic.encode() + payload.encode()
        
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/\
              TCP(sport=client_port, dport=mqtt_port, flags="PA")/\
              Raw(load=mqtt_pub)
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"    [✓] Created {message_count} MQTT messages")

def main():
    print_header()
    
    # Create output directory
    output_dir = "./pcap_samples"
    os.makedirs(output_dir, exist_ok=True)
    
    attack_dir = "./attack_samples"
    os.makedirs(attack_dir, exist_ok=True)
    
    print("[*] Output directories created")
    print(f"    Normal traffic: {output_dir}")
    print(f"    Attack traffic: {attack_dir}")
    print()
    
    print("════════════════════════════════════════════════════════════════")
    print("Generating PCAP Files")
    print("════════════════════════════════════════════════════════════════")
    print()
    
    # Normal traffic samples
    print("--- Normal Traffic Samples ---")
    create_normal_traffic(f"{output_dir}/normal_mixed.pcap", 200)
    create_mqtt_traffic(f"{output_dir}/mqtt_sensor.pcap", 50)
    
    # Attack samples
    print("\n--- Attack Traffic Samples ---")
    create_syn_flood(f"{attack_dir}/syn_flood.pcap", 2000)
    create_udp_flood(f"{attack_dir}/udp_flood.pcap", 3000)
    create_icmp_flood(f"{attack_dir}/icmp_flood.pcap", 2000)
    create_ping_of_death(f"{attack_dir}/ping_of_death.pcap")
    create_port_scan_syn(f"{attack_dir}/tcp_syn_scan.pcap", 50)
    create_port_scan_connect(f"{attack_dir}/tcp_connect_scan.pcap", 30)
    create_udp_scan(f"{attack_dir}/udp_scan.pcap", 40)
    create_http_flood(f"{attack_dir}/http_flood.pcap", 300)
    
    print()
    print("════════════════════════════════════════════════════════════════")
    print("Generation Complete!")
    print("════════════════════════════════════════════════════════════════")
    print()
    
    print("Normal traffic files:")
    for f in os.listdir(output_dir):
        if f.endswith('.pcap'):
            size = os.path.getsize(os.path.join(output_dir, f))
            print(f"  {f} - {size/1024:.1f} KB")
    
    print("\nAttack traffic files:")
    for f in os.listdir(attack_dir):
        if f.endswith('.pcap'):
            size = os.path.getsize(os.path.join(attack_dir, f))
            print(f"  {f} - {size/1024:.1f} KB")
    
    print()
    print("To analyze:")
    print(f"  ./bin/dpi_engine {output_dir}/normal_mixed.pcap")
    print(f"  ./bin/dpi_engine_ids {attack_dir}/syn_flood.pcap")
    print()

if __name__ == "__main__":
    main()
