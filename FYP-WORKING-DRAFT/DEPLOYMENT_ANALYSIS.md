# ELAI System - Complete Architecture Analysis & Deployment Strategy

## PART 1: WHAT THE CODE ACTUALLY DOES

### Current Testing Flow (Your Local Setup)
```
┌─────────────────────────────────────────────────────────────┐
│ Windows Machine                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  test_inference_traffic.py                                 │
│  ├─ Generates attack packets (spoofed IPs)                │
│  ├─ Uses scapy.send() to inject packets                   │
│  └─ Targets: 127.0.0.1:9000 (local interface)            │
│          ↓                                                 │
│  inference.py                                              │
│  ├─ scapy.sniff() captures those packets                  │
│  ├─ Layer 1: ML model predicts (SYN Flood, SQLi, etc.)   │
│  ├─ Layer 2: Payload analysis (keywords like SELECT)      │
│  ├─ Layer 3: Behavior analysis (port scanning patterns)   │
│  └─ Builds alert object with all features                │
│          ↓                                                 │
│  POST to http://localhost:4000/api/alerts ← ENV VAR!     │
│          ↓                                                 │
│  Dashboard Server (Node.js on :4000)                      │
│  ├─ Receives alert via POST endpoint                      │
│  ├─ Stores in MySQL database                             │
│  └─ Broadcasts to clients via WebSocket                   │
│          ↓                                                 │
│  Browser Dashboard                                        │
│  └─ Displays alert with explanations                      │
│                                                            │
└─────────────────────────────────────────────────────────────┘
```

### The 3-Layer Detection System

**Layer 1: Machine Learning (RF Model)**
- Trained on features: packet length, TCP flags, bit rate, port entropy, etc.
- 50 decision trees predicting 7 classes: Normal, SYN_Flood, SQL_Injection, etc.
- Model artifacts: `FYP/edge_ai_artifacts/` (rf_model.joblib, scaler.joblib, etc.)

**Layer 2: DPI (Deep Packet Inspection)**
- Scans TCP payload for attack signatures
- Detects: "SELECT ... FROM", "' OR '1'='1'", "<script>", "cat /etc/passwd", etc.
- Returns: Clean OR specific attack type (SQL_Injection, XSS_Injection, etc.)

**Layer 3: Behavior Analysis**
- Tracks IP history over 15-second rolling window
- Detects: Port scans (10+ ports), brute force attempts (25+ connections on few ports)
- Calculates entropy of port diversity

**Priority**: Layer 2 > Layer 3 > Layer 1 (signature > behavior > statistic)

---

## PART 2: WHAT BREAKS IN VM SCENARIO

### Problem 1: Network Isolation
```
Kali VM (different subnet)     Ubuntu VM (different subnet)
└─ Where does inference.py run?
   └─ On Ubuntu? Can't sniff Kali's packets (different network)
   └─ On Kali? alerts need to reach Ubuntu dashboard
```

### Problem 2: Port 22 Excluded
```python
sniff(
    iface=IFACE_NAME,
    filter="not port 22 and not icmp",  # ← SSH traffic ignored!
    prn=analyze_packet,
    store=False,
)
```
This is for testing - excludes SSH (else interferesewith lab SSH) and ICMP (ping).

### Problem 3: Packet Capture Requires Sudo
```python
# This runs as root, needs sudo privilege
sniff(iface=..., filter=..., prn=..., store=False)
```

### Problem 4: Alert URL is Environment Variable
```python
DASHBOARD_ALERT_URL = os.environ.get(
    "DASHBOARD_ALERT_URL",
    "http://localhost:4000/api/alerts"
)
```
**This is GOOD** - means we can redirect to Ubuntu's IP!

---

## PART 3: RECOMMENDED ARCHITECTURE (HYBRID APPROACH)

```
┌─────────────────────────────────┐         ┌─────────────────────────┐
│       UBUNTU VM                 │         │      KALI VM            │
├─────────────────────────────────┤         ├─────────────────────────┤
│                                 │         │                         │
│ Dashboard Server:               │         │ Attacker Tools:         │
│ ├─ Node.js app                 │         │ ├─ hping3 (SYN flood)   │
│ ├─ Port 4000                   │         │ ├─ nmap (port scan)     │
│ ├─ MySQL database              │         │ ├─ sqlmap (SQL injec.)  │
│ └─ WebSocket for alerts        │         │ ├─ curl (HTTP payloads) │
│                                 │         │ └─ Custom scripts       │
│                                 │         │                         │
└──────────────────┬──────────────┘         └────────────┬────────────┘
                   ↑                                     │
                   │ DASHBOARD_ALERT_URL=               │
                   │ http://ubuntu_ip:4000/api/alerts   │
                   │                                     │
               (Receives alerts)               (Sends attack packets)
                   ↑                                     │
                   └─────────────────────────────────────┤
                                                         │
                                              Attacks generated:
                                              hping3, nmap, sqlmap
                                              injected to network
                                                         │
                                                         ↓
┌────────────────────────────────────────────────────────────────┐
│                  KALI VM - NETWORK TRAFFIC                     │
├────────────────────────────────────────────────────────────────┤
│  Attack packets flow through eth0 interface                    │
│  These packets exist on the LANwhere inference.py can sniff   │
└────────────────────────────────────────────────────────────────┘
                                                         │
                                                         ↓
┌────────────────────────────────────────────────────────────────┐
│                  KALI VM - inference.py runs HERE              │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│ $ sudo DASHBOARD_ALERT_URL=http://ubuntu_ip:4000/api/alerts \│
│     python3 FYP/inference.py                                  │
│                                                                │
│ ├─ Sniffs eth0 interface                                      │
│ ├─ Captures attack packets                                    │
│ ├─ Runs 3-layer detection                                    │
│ ├─ Creates alert object                                      │
│ └─ POST to http://ubuntu_ip:4000/api/alerts ✓               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
                            ↓
        (Alert received and stored in MySQL)
```

---

## PART 4: WHY THIS APPROACH

| Aspect | Their Approach | Our Approach | Result |
|--------|---|---|---|
| **Where inference runs** | Ubuntu VM | Kali VM | ✅ Kali = where traffic originates |
| **Packet capture** | Requires seeing Kali traffic on Ubuntu | Natural - traffic on same network | ✅ GOOD |
| **Dashboard location** | Same as inference (Ubuntu) | Separate on Ubuntu | ✅ GOOD (cleaner) |
| **Database access** | Local on Ubuntu | Remote from... wait, inference doesn't access DB! | ✅ GOOD |
| **Real-world simulation** | Monolithic | Distributed | ✅ REALISTIC |

**Key insight**: Your `inference.py` ONLY needs:
- Network interface to sniff
- Environment variable for dashboard URL
- It does NOT access the database directly (alert handler does via HTTP!)

---

## PART 5: ACTUAL DEPLOYMENT STEPS

### Step 1: VirtualBox Setup (30 minutes)
1. Download Ubuntu Server 22.04 LTS ISO
2. Download Kali Linux VirtualBox OVA
3. Create Ubuntu VM: 4GB RAM, 2 CPUs, NAT Network `edge-network`
4. Import Kali VM: same NAT Network `edge-network`
5. Boot both, verify they can ping each other

### Step 2: Ubuntu Setup (20 minutes)
```bash
# Install Node.js
sudo apt update && sudo apt install nodejs npm

# Install MySQL
sudo apt install mysql-server

# Configure database
mysql -u root -p
> CREATE DATABASE elai;
> CREATE USER 'elai_user'@'localhost' IDENTIFIED BY 'MyPass123';
> GRANT ALL PRIVILEGES ON elai.* TO 'elai_user'@'localhost';
> FLUSH PRIVILEGES;

# Copy dashboard folder
cp -r project_root/elai-dashboard ~/dashboard
cd ~/dashboard

# Install dependencies
npm install

# Run database migrations
npm run migrate

# Start dashboard
npm run dev
# Listens on http://ubuntu_ip:4000
```

### Step 3: Kali Setup (25 minutes)
```bash
# Install Python & dependencies
sudo apt update && sudo apt install python3 python3-pip

# Install requirements for inference
pip3 install scapy pandas joblib

# Copy FYP folder
cp -r project_root/FYP ~/FYP

# Test attack tools installed
which hping3 nmap

# Run inference.py WITH environment variable pointing to Ubuntu
sudo DASHBOARD_ALERT_URL=http://10.0.2.15:4000/api/alerts \
     python3 ~/FYP/inference.py

# Output should show:
# [*] Protected VM IP Address: 10.0.2.X
# [*] Sniffing on interface: eth0. Multi-Layer Defense Active.
```

### Step 4: Test with Attacks (15 minutes)
```bash
# ON KALI VM - In a new terminal

# SYN Flood
sudo hping3 -S -p 80 --flood <ubuntu_ip>

# Port Scan
sudo nmap -sS -p 1-1000 <ubuntu_ip>

# SQL Injection  
curl "http://<ubuntu_ip>:9000/?user=admin' OR '1'='1'"

# Watch alerts in Ubuntu: http://ubuntu_ip:4000
# Should see new alerts appearing in real-time!
```

---

## PART 6: FILE STRUCTURE FOR DEPLOYMENT

### Ubuntu VM
```
~/dashboard/               ← Node.js dashboard server
├─ package.json
├─ server/
├─ client/
├─ drizzle/
├─ .env (DATABASE_URL set to localhost)
└─ node_modules/

MySQL running on :3306
```

### Kali VM
```
~/FYP/                     ← inference.py & models
├─ inference.py
├─ edge_ai_artifacts/      ← Pre-trained RF model
│  ├─ rf_model.joblib
│  ├─ scaler.joblib
│  ├─ label_encoder.joblib
│  └─ feature_columns.joblib
├─ test_inference_traffic.py (NOT used in VM - it's on Windows)
└─ ...
```

---

## PART 7: KEY CONFIGURATION CHANGES NEEDED

### 1. inference.py - Check if needs changes
Currently:
```python
DASHBOARD_ALERT_URL = os.environ.get(
    "DASHBOARD_ALERT_URL",
    "http://localhost:4000/api/alerts"
)
```
✅ Already supports environment variable - NO CHANGE NEEDED

### 2. Server - Check if needs changes
`server/index.ts` has `/api/alerts` endpoint that accepts POST ✅ READY

### 3. Database - MySQL
Default `.env` is `mysql://elai_user:MyPass123@localhost:3306/elai`
✅ This works if MySQL running on Ubuntu VM

### 4. WebSocket - Should broadcast alerts
`websocket.ts` has `broadcastAlert()` function ✅ READY

---

## SUMMARY: THE ACTUAL APPROACH

NOT "Their approach" (all on one VM)  
NOT "Your approach" (fully distributed edge agents)  
**HYBRID: Split responsibilities intelligently**

```
Kali = Where attacks happen + Where inference runs
  └─ Has the attack tools, network captures traffic naturally

Ubuntu = Dashboard + Database
  └─ Central monitoring/visualization point

This way:
✅ Attacks are naturally on the network interference sniffs
✅ Real-world simulation (separate inference/dashboard)
✅ Minimal code changes
✅ Easy to test and debug
```

---

## FILES & COMMANDS SUMMARY

### To Copy to Ubuntu
```
project_root/elai-dashboard/  → entire folder
```

### To Copy to Kali
```
project_root/FYP/             → entire folder
project_root/explainable_ai/  → for alert explanations
```

### Environment Variable (on Kali)
```bash
DASHBOARD_ALERT_URL=http://<UBUNTU_IP>:4000/api/alerts
```

### Database (on Ubuntu)
```
DATABASE_URL=mysql://elai_user:MyPass123@localhost:3306/elai
```

---

Ready? Should I create step-by-step commands for each VM?
