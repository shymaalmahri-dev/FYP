import os
import time
import random
import math
from collections import Counter
from scapy.all import IP, TCP, UDP, ICMP, wrpcap, RandIP, RandShort

PACKET_COUNT = 5000
TARGET_IP = "192.168.1.100"
OUTPUT_DIR = "synthetic_data"
os.makedirs(OUTPUT_DIR, exist_ok=True)

random.seed(42)

# ─────────────────────────────────────────────
# NORMAL IoT Traffic  (diverse, realistic, bursty)
# ─────────────────────────────────────────────
def generate_normal_traffic():
    print(f"[*] Generating {PACKET_COUNT} Normal packets (mixed IoT types)...")
    packets = []
    base_time = time.time()
    elapsed = 0.0

    traffic_weights = {
        "mqtt_sensor":   30,
        "mqtt_burst":    10,   # legitimate bursty IoT (was the FP source)
        "http":          20,
        "ssh":           10,
        "dns_udp":       15,
        "coap_udp":      10,
        "background":     5,
    }
    types = list(traffic_weights.keys())
    weights = list(traffic_weights.values())
    src_pool = ["192.168.1.50", "192.168.1.51", "192.168.1.52",
                "192.168.1.53", "10.0.0.10"]

    for i in range(PACKET_COUNT):
        t_type = random.choices(types, weights=weights)[0]
        src = random.choice(src_pool)

        if t_type == "mqtt_sensor":
            iat = random.uniform(0.1, 2.0)
            pkt = IP(src=src, dst=TARGET_IP) / TCP(sport=random.randint(1024,65535), dport=1883, flags="PA")

        elif t_type == "mqtt_burst":
            # IoT sensor batch-uploading — fast but NOT an attack
            iat = random.uniform(0.005, 0.05)
            pkt = IP(src=src, dst=TARGET_IP) / TCP(sport=random.randint(1024,65535), dport=1883, flags="PA")

        elif t_type == "http":
            iat = random.uniform(0.05, 1.0)
            flags = random.choice(["S", "A", "PA"])
            dport = random.choice([80, 443, 8080])
            pkt = IP(src=src, dst=TARGET_IP) / TCP(sport=random.randint(1024,65535), dport=dport, flags=flags)

        elif t_type == "ssh":
            iat = random.uniform(0.1, 5.0)
            pkt = IP(src=src, dst=TARGET_IP) / TCP(sport=random.randint(1024,65535), dport=22, flags="PA")

        elif t_type == "dns_udp":
            iat = random.uniform(0.2, 5.0)
            pkt = IP(src=src, dst=TARGET_IP) / UDP(sport=random.randint(1024,65535), dport=53)

        elif t_type == "coap_udp":
            iat = random.uniform(0.5, 10.0)
            pkt = IP(src=src, dst=TARGET_IP) / UDP(sport=random.randint(1024,65535), dport=5683)

        else:  # background
            iat = random.uniform(5.0, 60.0)
            dport = random.choice([22, 443, 80])
            pkt = IP(src=src, dst=TARGET_IP) / TCP(sport=random.randint(1024,65535), dport=dport, flags="A")

        elapsed += iat
        pkt.time = base_time + elapsed
        packets.append(pkt)

    wrpcap(f"{OUTPUT_DIR}/Normal_Traffic.pcap", packets)
    print(f"  Done. {len(packets)} packets.")


# ─────────────────────────────────────────────
# SYN FLOOD — from ATTACKER side (4 variants)
# ─────────────────────────────────────────────
def generate_syn_flood():
    print(f"[*] Generating {PACKET_COUNT} SYN Flood packets (4 variants)...")
    packets = []
    base_time = time.time()
    elapsed = 0.0

    for i in range(PACKET_COUNT):
        variant = random.choices(
            ["classic", "slow_syn", "multi_port", "ack_flood"],
            weights=[50, 20, 20, 10])[0]

        if variant == "classic":
            iat = random.uniform(0.0005, 0.005)
            dport = random.choice([80, 443])
            pkt = IP(src=str(RandIP()), dst=TARGET_IP) / TCP(
                sport=int(RandShort()), dport=dport, flags="S",
                window=random.randint(512, 4096))

        elif variant == "slow_syn":
            iat = random.uniform(0.05, 0.3)
            dport = random.choice([80, 443, 22, 8080])
            pkt = IP(src=str(RandIP()), dst=TARGET_IP) / TCP(
                sport=int(RandShort()), dport=dport, flags="S",
                window=random.randint(1024, 8192))

        elif variant == "multi_port":
            iat = random.uniform(0.001, 0.01)
            dport = random.randint(1, 1024)
            pkt = IP(src=str(RandIP()), dst=TARGET_IP) / TCP(
                sport=int(RandShort()), dport=dport, flags="S",
                window=random.randint(512, 2048))

        else:  # ack_flood
            iat = random.uniform(0.0005, 0.003)
            dport = random.choice([80, 443])
            pkt = IP(src=str(RandIP()), dst=TARGET_IP) / TCP(
                sport=int(RandShort()), dport=dport, flags="A",
                window=random.randint(0, 512))

        elapsed += iat
        pkt.time = base_time + elapsed
        packets.append(pkt)

    wrpcap(f"{OUTPUT_DIR}/SYN_Flood_Traffic.pcap", packets)
    print(f"  Done. {len(packets)} packets.")


# ─────────────────────────────────────────────
# PORT SCAN — from ATTACKER side (4 scan types)
# ─────────────────────────────────────────────
def generate_port_scan():
    print(f"[*] Generating {PACKET_COUNT} Port Scan packets (4 scan types)...")
    packets = []
    base_time = time.time()
    elapsed = 0.0
    attacker_ip = "10.0.0.99"

    for i in range(PACKET_COUNT):
        scan_type = random.choices(
            ["syn_scan", "fin_scan", "null_scan", "connect_scan"],
            weights=[60, 15, 15, 10])[0]

        if scan_type == "syn_scan":
            iat = random.uniform(0.005, 0.02)
            dport = (i % 65000) + 1
            pkt = IP(src=attacker_ip, dst=TARGET_IP) / TCP(
                sport=random.randint(1024, 65535), dport=dport, flags="S",
                window=random.randint(1024, 4096))

        elif scan_type == "fin_scan":
            iat = random.uniform(0.01, 0.05)
            dport = random.randint(1, 65535)
            pkt = IP(src=attacker_ip, dst=TARGET_IP) / TCP(
                sport=random.randint(1024, 65535), dport=dport, flags="F",
                window=0)

        elif scan_type == "null_scan":
            iat = random.uniform(0.01, 0.05)
            dport = random.randint(1, 65535)
            pkt = IP(src=attacker_ip, dst=TARGET_IP) / TCP(
                sport=random.randint(1024, 65535), dport=dport, flags="",
                window=0)

        else:  # connect_scan
            iat = random.uniform(0.05, 0.2)
            dport = random.randint(1, 1024)
            pkt = IP(src=attacker_ip, dst=TARGET_IP) / TCP(
                sport=random.randint(1024, 65535), dport=dport, flags="S",
                window=random.randint(2048, 8192))

        elapsed += iat
        pkt.time = base_time + elapsed
        packets.append(pkt)

    wrpcap(f"{OUTPUT_DIR}/Port_Scan_Traffic.pcap", packets)
    print(f"  Done. {len(packets)} packets.")


generate_normal_traffic()
generate_syn_flood()
generate_port_scan()
print("\n[SUCCESS] All synthetic datasets generated in \'synthetic_data/\'")
print("Run createfile.py next, then train.py.")
