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
