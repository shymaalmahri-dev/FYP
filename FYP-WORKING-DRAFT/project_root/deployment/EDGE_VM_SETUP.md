# ELAI Edge VM Setup

## Goal

Run the lab with:

- `Kali VM` as attacker
- `Edge VM` as protected host + capture point + inference + block agent
- `Ubuntu VM` as dashboard + MySQL + central SOC backend
- `Windows host browser` as the viewer for the Ubuntu dashboard

Runtime flow:

`Kali -> Edge VM (capture + inference + local block agent) -> Ubuntu dashboard/API -> Windows browser`

## Network Layout

All three VMs should share the same VirtualBox host-only network on Adapter 2.

- Ubuntu VM host-only IP: `192.168.56.101`
- Kali VM host-only IP: `192.168.56.102`
- Edge VM host-only IP: `192.168.56.103`

Adapter plan for each VM:

1. Adapter 1: `NAT`
2. Adapter 2: `Host-Only Adapter`

## Create the Edge VM

1. In VirtualBox click `New`.
2. Create another Ubuntu VM. Ubuntu Server is enough.
3. Give it:
   - 2 CPU cores minimum
   - 2 GB RAM minimum
   - 20 GB disk or more
4. In `Settings -> Network`:
   - Adapter 1: NAT
   - Adapter 2: Host-Only Adapter
5. Make sure Adapter 2 uses the same host-only network as Kali and Ubuntu.

## Give the Edge VM a Stable Host-Only IP

Set the edge VM host-only interface to:

- interface: `enp0s8`
- IP: `192.168.56.103/24`

You can adapt `deployment/ubuntu/01-elai-hostonly-enp0s8.yaml` by changing the address to:

```yaml
addresses:
  - 192.168.56.103/24
```

Then run:

```bash
sudo netplan apply
ip addr show enp0s8
```

## What Runs Where

### Ubuntu VM

Runs:

- `elai-dashboard`
- MySQL

The dashboard alert API should be reachable from the edge VM at:

```text
http://192.168.56.101:4000/api/alerts
```

### Edge VM

Runs:

- `FYP/inference.py`
- `FYP/edge_block_agent.py`

Set the inference env on the edge VM to:

- `PROTECTED_VM_IP=192.168.56.103`
- `PROTECTED_VM_CIDR=192.168.56.103/24`
- `CAPTURE_INTERFACE=enp0s8`
- `DASHBOARD_ALERT_URL=http://192.168.56.101:4000/api/alerts`

The edge block agent listens on:

```text
http://192.168.56.103:8787/block-ip
```

### Kali VM

Attack the edge VM at:

```text
192.168.56.103
```

## Dashboard Blocking Flow

When you click `Block` in the dashboard:

1. The dashboard sends the chosen source IP to the edge block agent.
2. The edge agent adds a local firewall drop rule on the edge VM.
3. The dashboard records the blocked IP in MySQL.
4. Existing alerts for that source are marked as blocked in the UI.

## Files To Copy To The Edge VM

Copy these from the repo:

- `FYP/inference.py`
- `FYP/edge_block_agent.py`
- `deployment/ubuntu/run_inference.sh`
- `deployment/ubuntu/run_edge_block_agent.sh`
- `deployment/ubuntu/elai-inference.env`
- `deployment/ubuntu/elai-inference.service`
- `deployment/ubuntu/elai-edge-block-agent.service`

## Edge VM One-Time Setup

If your Windows file server is serving the repo root on port `8000`:

```bash
wget -O ~/FYP/inference.py http://192.168.56.1:8000/FYP/inference.py
wget -O ~/FYP/edge_block_agent.py http://192.168.56.1:8000/FYP/edge_block_agent.py
wget -O ~/FYP/run_inference.sh http://192.168.56.1:8000/deployment/ubuntu/run_inference.sh
wget -O ~/FYP/run_edge_block_agent.sh http://192.168.56.1:8000/deployment/ubuntu/run_edge_block_agent.sh
wget -O /tmp/elai-inference.env http://192.168.56.1:8000/deployment/ubuntu/elai-inference.env
wget -O /tmp/elai-inference.service http://192.168.56.1:8000/deployment/ubuntu/elai-inference.service
wget -O /tmp/elai-edge-block-agent.service http://192.168.56.1:8000/deployment/ubuntu/elai-edge-block-agent.service
chmod +x ~/FYP/run_inference.sh ~/FYP/run_edge_block_agent.sh
sudo mkdir -p /etc/elai
sudo cp /tmp/elai-inference.env /etc/elai/inference.env
sudo cp /tmp/elai-inference.service /etc/systemd/system/elai-inference.service
sudo cp /tmp/elai-edge-block-agent.service /etc/systemd/system/elai-edge-block-agent.service
```

Edit `/etc/elai/inference.env` on the edge VM so it contains:

```text
PROTECTED_VM_IP=192.168.56.103
PROTECTED_VM_CIDR=192.168.56.103/24
CAPTURE_INTERFACE=enp0s8
DASHBOARD_ALERT_URL=http://192.168.56.101:4000/api/alerts
EDGE_BLOCK_AGENT_TOKEN=change-me
```

Then enable both services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now elai-inference
sudo systemctl enable --now elai-edge-block-agent
```

## Ubuntu Dashboard Env For Edge Blocking

On the Ubuntu dashboard VM set:

```text
EDGE_BLOCK_AGENT_URL=http://192.168.56.103:8787/block-ip
EDGE_BLOCK_AGENT_TOKEN=change-me
```

Then restart the dashboard backend.
