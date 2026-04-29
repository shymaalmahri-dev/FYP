


from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
import os

# 1. Tweak these to match your exact filenames
pcap_files = {
    r"data\Distance.pcap": "Normal",
    r"data\Heart_Rate.pcap": "Normal",
    r"data\Ubuntu_Background.pcap": "Normal", 
    r"data\DDoS TCP SYN Flood Attacks.pcap": "SYN_Flood",
    r"data\Port Scanning attack.pcap": "Port_Scanning",
    r"data\20220701-managed-mode-port-scanning-v2.pcap":"Port_Scanning",
    r"data\capture-1.pcap":"Normal",
    r"data\capture-2.pcap":"Normal",
    r"data\capture-3.pcap":"Normal",
    r"data\capture-4.pcap":"Normal",
    r"data\reduced.pcap":"Normal",
    r"data\normaldata.pcap":"Normal",
    r"data\SYN_flood_port80.pcap": "SYN_Flood",
    r"data\SYN_flood_port443.pcap": "SYN_Flood",
    r"data\SYN_flood_port500.pcap": "SYN_Flood",
    r"data\SYN_flood.pcap": "SYN_Flood",
    r"synthetic_data\Normal_Traffic.pcap": "Normal",
    r"synthetic_data\SYN_Flood_Traffic.pcap": "SYN_Flood",
    r"synthetic_data\Port_Scan_Traffic.pcap": "Port_Scanning"
}

output_csv = "training_data_iot.csv"

import math # ADD THIS TO THE TOP OF YOUR FILE

# --- STATE TRACKERS FOR CONTEXT FEATURES ---
ip_history = {}
port_history = {}
byte_history = {} # NEW: Tracks bytes per second

def reset_state():
    global ip_history, port_history, byte_history
    ip_history.clear()
    port_history.clear()
    byte_history.clear()

def clean_old_state(current_time, window_size=1.5):
    for ip in list(ip_history.keys()):
        ip_history[ip] = [t for t in ip_history[ip] if current_time - t <= window_size]
        if not ip_history[ip]: del ip_history[ip]
            
    for ip in list(port_history.keys()):
        port_history[ip] = {t: p for t, p in port_history[ip].items() if current_time - t <= window_size}
        if not port_history[ip]: del port_history[ip]
            
    for ip in list(byte_history.keys()):
        byte_history[ip] = {t: b for t, b in byte_history[ip].items() if current_time - t <= window_size}
        if not byte_history[ip]: del byte_history[ip]

def calculate_entropy(port_list):
    """Calculates the Shannon Entropy of destination ports."""
    if not port_list: return 0.0
    port_counts = {}
    for p in port_list: port_counts[p] = port_counts.get(p, 0) + 1
    entropy = 0.0
    for count in port_counts.values():
        prob = count / len(port_list)
        entropy -= prob * math.log2(prob)
    return entropy

def extract_consistent_features(packet, label):
    if not IP in packet: return None
    
    src_ip = packet[IP].src
    current_time = float(packet.time) 
    pkt_length = len(packet)
    
    clean_old_state(current_time)
    
    if src_ip not in ip_history: ip_history[src_ip] = []
    if src_ip not in byte_history: byte_history[src_ip] = {}
    
    ip_history[src_ip].append(current_time)
    byte_history[src_ip][current_time] = pkt_length
    
    # Calculate IAT (Inter-Arrival Time)
    iat = 0.0
    if len(ip_history[src_ip]) > 1:
        iat = ip_history[src_ip][-1] - ip_history[src_ip][-2]

    # Initialize the expanded dictionary (Now approaching 30 features)
    features = {
        "pkt_len": pkt_length,
        "ip_proto": packet[IP].proto,
        "ip_ttl": packet[IP].ttl,
        "is_icmp": 1 if ICMP in packet else 0,
        
        # Extended TCP Flags
        "tcp_flags": 0, "is_syn": 0, "is_ack": 0, "is_rst": 0, "is_fin": 0, 
        "is_psh": 0, "is_urg": 0, "is_ece": 0, "is_cwr": 0,
        "tcp_win": 0, "payload_len": 0, "dport": 0,
        
        # Protocol Context
        "is_well_known_port": 0,
        "is_modbus": 0, "is_mqtt": 0, "is_http": 0, "is_dns": 0,
        
        # Behavioral/Statistical Flow Features
        "iat": iat,
        "pkt_rate": len(ip_history[src_ip]),
        "byte_rate": sum(byte_history[src_ip].values()),
        "unique_ports_hit": 0,
        "port_entropy": 0.0,
        "label": label
    }

    if TCP in packet or UDP in packet:
        if TCP in packet:
            flags = packet[TCP].flags
            features["tcp_flags"] = int(flags)
            features["is_syn"] = 1 if 'S' in flags else 0
            features["is_ack"] = 1 if 'A' in flags else 0
            features["is_rst"] = 1 if 'R' in flags else 0
            features["is_fin"] = 1 if 'F' in flags else 0
            features["is_psh"] = 1 if 'P' in flags else 0
            features["is_urg"] = 1 if 'U' in flags else 0
            features["is_ece"] = 1 if 'E' in flags else 0
            features["is_cwr"] = 1 if 'C' in flags else 0
            
            features["tcp_win"] = packet[TCP].window
            features["payload_len"] = len(packet[TCP].payload)
            features["dport"] = packet[TCP].dport
        elif UDP in packet:
            features["payload_len"] = len(packet[UDP].payload)
            features["dport"] = packet[UDP].dport
            
        features["is_well_known_port"] = 1 if features["dport"] < 1024 else 0
        features["is_modbus"] = 1 if features["dport"] == 502 else 0
        features["is_mqtt"] = 1 if features["dport"] == 1883 else 0
        features["is_http"] = 1 if features["dport"] in [80, 443, 8080] else 0
        features["is_dns"] = 1 if features["dport"] == 53 else 0
        
        if src_ip not in port_history: port_history[src_ip] = {}
        port_history[src_ip][current_time] = features["dport"]
        
        # Entropy and Unique Ports
        recent_ports = list(port_history[src_ip].values())
        features["unique_ports_hit"] = len(set(recent_ports))
        features["port_entropy"] = calculate_entropy(recent_ports)

    return features

# 2. Process the files
final_dataset = []

for filename, label in pcap_files.items():
    if not os.path.exists(filename):
        print(f"[!] File not found: {filename}")
        continue
        
    print(f"[*] Processing {filename} ({label})...")
    reset_state() # Crucial!
    
    packets = rdpcap(filename, count=20000) 
    
    for pkt in packets:
        feat = extract_consistent_features(pkt, label)
        if feat:
            final_dataset.append(feat)

# 3. Save to CSV
df = pd.DataFrame(final_dataset)
df.to_csv(output_csv, index=False)
print(f"\n[SUCCESS] Created {output_csv} with {len(df)} rows.")
print(df['label'].value_counts())