# Sailesh Spy — Network Traffic Analyzer

A Kali Linux tool to monitor DNS queries and HTTP requests on your
network, showing which websites each client IP is visiting — in plain text.

---

## ⚠️  Legal Notice

> **Only use this tool on networks you own or have explicit written
> permission to monitor. Unauthorized interception of network traffic
> is illegal under the CFAA, ECPA (US), Computer Misuse Act (UK),
> IT Act (India), and equivalents worldwide.**

---

## Features

- 🔍 **DNS sniffer** — captures every domain lookup (port 53 UDP)
- 🌐 **HTTP inspector** — captures Host headers + URL paths (port 80)
- 👥 **Client IP tracking** — groups traffic per source IP
- 🆕 **NEW domain flag** — highlights first-time visits per client
- 📊 **Live web dashboard** (`saileshspy_dashboard.py`) — browser UI
- 📁 **CSV log export** — auto-saved on exit
- 🎨 **Color-coded terminal output**

> **Note:** HTTPS traffic (port 443) is encrypted. You'll see DNS lookups
> for HTTPS sites but not the URL paths. Use on HTTP (port 80) only for
> full URL inspection.

---

## Installation (Kali Linux)

```bash
# Dependencies are auto-installed, but you can pre-install:
sudo apt install python3-scapy -y
pip3 install flask --break-system-packages

# Clone / copy files to your working directory
chmod +x saileshspy.py saileshspy_dashboard.py
```

---

## Usage

### 1. Terminal Mode (saileshspy.py)

```bash
# Auto-detect interface
sudo python3 saileshspy.py

# Specify interface
sudo python3 saileshspy.py -i eth0
sudo python3 saileshspy.py -i wlan0

# DNS only
sudo python3 saileshspy.py -i eth0 --dns-only

# HTTP only
sudo python3 saileshspy.py -i eth0 --http-only

# List interfaces
sudo python3 saileshspy.py --list-interfaces
```

**Sample output:**
```
14:32:01  192.168.1.105     [DNS]  google.com             [NEW]
14:32:01  192.168.1.105     [DNS]  apis.google.com
14:32:02  192.168.1.88      [HTTP] example.com   → /index.html  [NEW]
14:32:03  192.168.1.42      [DNS]  youtube.com            [NEW]
```

### 2. Web Dashboard Mode (saileshspy_dashboard.py)

```bash
sudo python3 saileshspy_dashboard.py -i eth0
# Open browser → http://localhost:5000
```

Features:
- Real-time live feed with animations
- Client sidebar with per-IP stats
- Click a client IP to filter their traffic
- Auto-scroll live feed

---

## How It Works

```
Your Network
    │
    ├── Client 192.168.1.x  ──DNS query──►  Your machine (sniffing)
    ├── Client 192.168.1.y  ──HTTP GET──►       │
    └── Client 192.168.1.z  ──DNS query──►      ▼
                                          Sailesh Spy captures
                                          + displays in plain text
```

The tool runs in **promiscuous mode** on the specified interface,
capturing packets matching the BPF filter `udp port 53 or tcp port 80`.

---

## Tips

- Put your interface in **monitor/promiscuous mode** for best results:
  ```bash
  sudo ip link set eth0 promisc on
  ```
- For Wi-Fi: use **monitor mode** with `airmon-ng`
  ```bash
  sudo airmon-ng start wlan0
  sudo python3 saileshspy.py -i wlan0mon
  ```
- Run on a **router/gateway** to see all network traffic

---

## Files

| File | Description |
|------|-------------|
| `saileshspy.py` | Terminal-based sniffer |
| `saileshspy_dashboard.py` | Flask web dashboard |
| `saileshspy_*.log` | Auto-generated CSV logs |
