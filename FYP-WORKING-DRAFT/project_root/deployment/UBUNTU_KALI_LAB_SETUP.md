# Ubuntu + Kali Lab Setup

## Goal

Run the first realistic lab version of ELAI with:

- Ubuntu Server:
  - `elai-dashboard`
  - MySQL
  - `FYP/inference.py`
- Kali:
  - attack generation only

Traffic flow:

`Kali attack traffic -> Ubuntu inference.py sniffing -> Ubuntu dashboard alerting`

## Files Included In This Bundle

- `elai-dashboard/`
- `FYP/`
- `explainable_ai/`
- `.env.example`

## What Ubuntu Needs

- Node.js and npm
- Python 3 and pip
- MySQL
- packet capture permissions

## What Kali Needs

- `hping3`
- `nmap`

## Recommended VirtualBox Networking

Use 2 adapters on both VMs:

1. Adapter 1: NAT
2. Adapter 2: Host-Only Adapter

This gives:

- internet inside each VM
- direct connectivity between Ubuntu, Kali, and the Windows host

## Runtime Setup Summary

On Ubuntu:

1. unzip this bundle
2. install dashboard dependencies in `elai-dashboard/`
3. create the dashboard `.env`
4. start MySQL
5. start the dashboard
6. run `FYP/inference.py`

On Kali:

1. confirm Ubuntu IP
2. run attack commands against Ubuntu

## Expected Test Commands From Kali

SYN flood:

```bash
sudo hping3 -S -p 80 --flood <UBUNTU_IP>
```

Port scan:

```bash
sudo nmap -sS -p 1-1000 <UBUNTU_IP>
```

## Notes

- For the first lab, `inference.py` and the dashboard can both run on Ubuntu.
- `DASHBOARD_ALERT_URL` can stay `http://localhost:4000/api/alerts` if the dashboard is running on the same Ubuntu VM.
- If later you split the dashboard and inference onto different machines, only the alert URL needs to change.

## Make Inference Persistent

If the host-only IP on `enp0s8` keeps disappearing after reboot, do not keep recreating
`run_inference.sh` by hand. Use the deployment files in [`deployment/ubuntu/`](./ubuntu)
once, then let Ubuntu restart the service automatically.

### 1. Copy the launcher and service files on Ubuntu

```bash
sudo mkdir -p /etc/elai
cp ~/project_root/deployment/ubuntu/run_inference.sh ~/FYP/run_inference.sh
chmod +x ~/FYP/run_inference.sh
sudo cp ~/project_root/deployment/ubuntu/elai-inference.env /etc/elai/inference.env
sudo cp ~/project_root/deployment/ubuntu/elai-inference.service /etc/systemd/system/elai-inference.service
```

If your Ubuntu repo lives somewhere other than `~/project_root`, adjust the source path in the
first and second `cp` commands.

### 2. Enable auto-start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now elai-inference
```

Useful checks:

```bash
sudo systemctl status elai-inference
sudo journalctl -u elai-inference -n 50 --no-pager
```

This launcher does three important things before starting Python:

- forces `enp0s8` up
- restores `192.168.56.101/24` if the host-only IP is missing
- passes the fixed ELAI env vars into `inference.py`

### 3. Optional but recommended: pin the host-only IP with Netplan

The most reliable long-term fix is to make Ubuntu keep the host-only address itself.
Copy the sample file and apply it:

```bash
sudo cp ~/project_root/deployment/ubuntu/01-elai-hostonly-enp0s8.yaml /etc/netplan/01-elai-hostonly-enp0s8.yaml
sudo netplan apply
```

That keeps `enp0s8` on `192.168.56.101/24` across reboots, which makes the Kali -> Ubuntu lab
much more stable.

## Optional: Enable Real Blocking On Ubuntu

If the same Ubuntu VM is both your monitored host and your dashboard host, you can run the
edge block agent locally so dashboard block actions apply real firewall rules on Ubuntu.

Copy these extra files:

```bash
cp ~/project_root/deployment/ubuntu/run_edge_block_agent.sh ~/FYP/run_edge_block_agent.sh
chmod +x ~/FYP/run_edge_block_agent.sh
sudo cp ~/project_root/deployment/ubuntu/elai-edge-block-agent.service /etc/systemd/system/elai-edge-block-agent.service
```

Set these dashboard variables in `elai-dashboard/.env`:

```text
EDGE_BLOCK_AGENT_URL=http://127.0.0.1:8787/block-ip
EDGE_BLOCK_AGENT_TOKEN=change-me
```

Then enable the local edge agent:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now elai-edge-block-agent
sudo systemctl status elai-edge-block-agent
```

When you click `Block` in the dashboard, Ubuntu will then add a local firewall rule instead of
only recording the action in MySQL.
