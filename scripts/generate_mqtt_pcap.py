#!/usr/bin/env python3
"""
IWSN Security - MQTT Synthetic PCAP Generator
Creates normal, unencrypted MQTT traffic for testing
Compatible with Paho MQTT parser
"""

import sys
import struct

try:
    from scapy.all import *
except ImportError:
    print("[!] Scapy not found. Install with: pip3 install scapy")
    sys.exit(1)

def create_mqtt_connect(client_id="test_client"):
    """Create MQTT CONNECT packet"""
    # MQTT CONNECT packet structure
    # Fixed header: 0x10 (CONNECT), remaining length
    # Variable header: Protocol Name (MQTT), Protocol Level (4), Connect Flags, Keep Alive
    # Payload: Client ID
    
    protocol_name = b'\x00\x04MQTT'  # Length (2 bytes) + "MQTT"
    protocol_level = b'\x04'  # MQTT 3.1.1
    connect_flags = b'\x02'  # Clean session
    keep_alive = b'\x00\x3c'  # 60 seconds
    
    client_id_bytes = client_id.encode('utf-8')
    client_id_len = struct.pack('>H', len(client_id_bytes))
    payload = client_id_len + client_id_bytes
    
    variable_header = protocol_name + protocol_level + connect_flags + keep_alive
    remaining_length = len(variable_header) + len(payload)
    
    # Fixed header
    fixed_header = b'\x10' + encode_remaining_length(remaining_length)
    
    return fixed_header + variable_header + payload

def create_mqtt_connack():
    """Create MQTT CONNACK packet"""
    # Fixed header: 0x20 (CONNACK)
    # Variable header: Session Present (0x00), Return Code (0x00 = accepted)
    fixed_header = b'\x20\x02'  # CONNACK, remaining length = 2
    variable_header = b'\x00\x00'  # Session Present = 0, Return Code = 0 (accepted)
    
    return fixed_header + variable_header

def create_mqtt_publish(topic, payload, qos=0, retain=False):
    """Create MQTT PUBLISH packet"""
    # Calculate flags
    dup = 0
    flags = (dup << 3) | (qos << 1) | (1 if retain else 0)
    fixed_header_byte = 0x30 | flags
    
    # Topic
    topic_bytes = topic.encode('utf-8')
    topic_len = struct.pack('>H', len(topic_bytes))
    
    # Payload
    payload_bytes = payload.encode('utf-8') if isinstance(payload, str) else payload
    
    # Variable header + payload
    variable_header = topic_len + topic_bytes
    
    # Add packet identifier if QoS > 0
    if qos > 0:
        packet_id = b'\x00\x01'  # Simple packet ID
        variable_header += packet_id
    
    message = variable_header + payload_bytes
    remaining_length = len(message)
    
    fixed_header = bytes([fixed_header_byte]) + encode_remaining_length(remaining_length)
    
    return fixed_header + message

def create_mqtt_subscribe(topic, qos=0):
    """Create MQTT SUBSCRIBE packet"""
    # Fixed header: 0x82 (SUBSCRIBE with QoS 1)
    packet_id = b'\x00\x01'  # Packet identifier
    
    topic_bytes = topic.encode('utf-8')
    topic_len = struct.pack('>H', len(topic_bytes))
    
    variable_header = packet_id
    payload = topic_len + topic_bytes + bytes([qos])
    
    message = variable_header + payload
    remaining_length = len(message)
    
    fixed_header = b'\x82' + encode_remaining_length(remaining_length)
    
    return fixed_header + message

def create_mqtt_suback():
    """Create MQTT SUBACK packet"""
    # Fixed header: 0x90 (SUBACK)
    packet_id = b'\x00\x01'  # Packet identifier
    return_code = b'\x00'  # QoS 0 granted
    
    variable_header = packet_id + return_code
    remaining_length = len(variable_header)
    
    fixed_header = b'\x90' + encode_remaining_length(remaining_length)
    
    return fixed_header + variable_header

def create_mqtt_pingreq():
    """Create MQTT PINGREQ packet"""
    return b'\xc0\x00'

def create_mqtt_pingresp():
    """Create MQTT PINGRESP packet"""
    return b'\xd0\x00'

def create_mqtt_disconnect():
    """Create MQTT DISCONNECT packet"""
    return b'\xe0\x00'

def encode_remaining_length(length):
    """Encode remaining length as per MQTT spec"""
    result = bytearray()
    while True:
        byte = length % 128
        length = length // 128
        if length > 0:
            byte |= 0x80
        result.append(byte)
        if length == 0:
            break
    return bytes(result)

def generate_mqtt_pcap(filename="mqtt_normal_traffic.pcap", num_sessions=3):
    """Generate a complete MQTT pcap file with multiple sessions"""
    print(f"[*] Generating MQTT PCAP: {filename}")
    print(f"    Sessions: {num_sessions}")
    
    packets = []
    broker_ip = "192.168.1.100"
    broker_port = 1883
    
    for session in range(num_sessions):
        client_ip = f"192.168.1.{10 + session}"
        client_port = 35000 + session * 10
        seq_num = 1000 * session
        ack_num = 2000 * session
        
        print(f"    [*] Session {session + 1}: Client {client_ip}:{client_port} -> Broker {broker_ip}:{broker_port}")
        
        # TCP 3-way handshake
        # SYN
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="S", seq=seq_num)
        packets.append(pkt)
        
        # SYN-ACK
        seq_num += 1
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="SA", seq=ack_num, ack=seq_num)
        packets.append(pkt)
        
        # ACK
        ack_num += 1
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="A", seq=seq_num, ack=ack_num)
        packets.append(pkt)
        
        # MQTT CONNECT
        mqtt_connect = create_mqtt_connect(f"client_{session + 1}")
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="PA", seq=seq_num, ack=ack_num)/Raw(load=mqtt_connect)
        packets.append(pkt)
        seq_num += len(mqtt_connect)
        
        # ACK for CONNECT
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="A", seq=ack_num, ack=seq_num)
        packets.append(pkt)
        
        # MQTT CONNACK
        mqtt_connack = create_mqtt_connack()
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="PA", seq=ack_num, ack=seq_num)/Raw(load=mqtt_connack)
        packets.append(pkt)
        ack_num += len(mqtt_connack)
        
        # ACK for CONNACK
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="A", seq=seq_num, ack=ack_num)
        packets.append(pkt)
        
        # MQTT SUBSCRIBE
        mqtt_subscribe = create_mqtt_subscribe(f"sensor/temperature/{session + 1}")
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="PA", seq=seq_num, ack=ack_num)/Raw(load=mqtt_subscribe)
        packets.append(pkt)
        seq_num += len(mqtt_subscribe)
        
        # ACK for SUBSCRIBE
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="A", seq=ack_num, ack=seq_num)
        packets.append(pkt)
        
        # MQTT SUBACK
        mqtt_suback = create_mqtt_suback()
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="PA", seq=ack_num, ack=seq_num)/Raw(load=mqtt_suback)
        packets.append(pkt)
        ack_num += len(mqtt_suback)
        
        # ACK for SUBACK
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="A", seq=seq_num, ack=ack_num)
        packets.append(pkt)
        
        # MQTT PUBLISH messages (multiple)
        topics = [
            (f"sensor/temperature/{session + 1}", f"{{\"temp\": {20 + session}, \"unit\": \"C\"}}"),
            (f"sensor/humidity/{session + 1}", f"{{\"humidity\": {50 + session * 5}, \"unit\": \"%\"}}"),
            (f"sensor/status/{session + 1}", f"{{\"status\": \"online\", \"battery\": {85 + session}}}"),
            (f"device/location/{session + 1}", f"{{\"lat\": {37.7 + session * 0.1}, \"lon\": {-122.4 + session * 0.1}}}"),
        ]
        
        for topic, payload in topics:
            mqtt_publish = create_mqtt_publish(topic, payload)
            pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="PA", seq=seq_num, ack=ack_num)/Raw(load=mqtt_publish)
            packets.append(pkt)
            seq_num += len(mqtt_publish)
            
            # ACK for PUBLISH
            pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="A", seq=ack_num, ack=seq_num)
            packets.append(pkt)
        
        # MQTT PINGREQ
        mqtt_pingreq = create_mqtt_pingreq()
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="PA", seq=seq_num, ack=ack_num)/Raw(load=mqtt_pingreq)
        packets.append(pkt)
        seq_num += len(mqtt_pingreq)
        
        # ACK for PINGREQ
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="A", seq=ack_num, ack=seq_num)
        packets.append(pkt)
        
        # MQTT PINGRESP
        mqtt_pingresp = create_mqtt_pingresp()
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="PA", seq=ack_num, ack=seq_num)/Raw(load=mqtt_pingresp)
        packets.append(pkt)
        ack_num += len(mqtt_pingresp)
        
        # ACK for PINGRESP
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="A", seq=seq_num, ack=ack_num)
        packets.append(pkt)
        
        # MQTT DISCONNECT
        mqtt_disconnect = create_mqtt_disconnect()
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="PA", seq=seq_num, ack=ack_num)/Raw(load=mqtt_disconnect)
        packets.append(pkt)
        seq_num += len(mqtt_disconnect)
        
        # ACK for DISCONNECT
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="A", seq=ack_num, ack=seq_num)
        packets.append(pkt)
        
        # TCP FIN handshake
        # FIN from client
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="FA", seq=seq_num, ack=ack_num)
        packets.append(pkt)
        seq_num += 1
        
        # ACK for FIN
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="A", seq=ack_num, ack=seq_num)
        packets.append(pkt)
        
        # FIN from broker
        pkt = Ether()/IP(src=broker_ip, dst=client_ip)/TCP(sport=broker_port, dport=client_port, flags="FA", seq=ack_num, ack=seq_num)
        packets.append(pkt)
        ack_num += 1
        
        # Final ACK
        pkt = Ether()/IP(src=client_ip, dst=broker_ip)/TCP(sport=client_port, dport=broker_port, flags="A", seq=seq_num, ack=ack_num)
        packets.append(pkt)
    
    # Write to pcap file
    wrpcap(filename, packets)
    print(f"    [✓] Created {len(packets)} packets")
    print(f"    [✓] MQTT sessions: {num_sessions}")
    print(f"    [✓] File saved: {filename}")
    print()
    print("[✓] MQTT PCAP generation complete!")

if __name__ == "__main__":
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║                                                                ║")
    print("║        IWSN Security - MQTT Synthetic PCAP Generator          ║")
    print("║           Normal, Unencrypted MQTT Traffic                    ║")
    print("║                                                                ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print()
    
    filename = "mqtt_normal_traffic.pcap"
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    
    num_sessions = 3
    if len(sys.argv) > 2:
        num_sessions = int(sys.argv[2])
    
    generate_mqtt_pcap(filename, num_sessions)
