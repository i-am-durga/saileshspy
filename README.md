# 🕵️ Sailesh Spy — Network Traffic Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-blue?style=for-the-badge&logo=linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Tool-Network%20Analyzer-red?style=for-the-badge"/>
</p>

<p align="center">
  A powerful Kali Linux network monitoring tool that captures <b>DNS queries</b> and <b>HTTP requests</b> from all clients on your network — showing exactly which websites each IP address is visiting, in plain text.
</p>

---

## ⚠️ Legal Disclaimer

> **This tool is for educational and authorized security testing purposes only.**  
> Only use it on networks you **own** or have **explicit written permission** to monitor.  
> Unauthorized interception of network traffic is illegal under the CFAA, ECPA (US),
> Computer Misuse Act (UK), IT Act (India), and equivalent laws worldwide.  
> The author is not responsible for any misuse.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 DNS Sniffer | Captures every domain lookup (UDP port 53) |
| 🌐 HTTP Inspector | Captures Host headers + URL paths (TCP port 80) |
| 👥 Client IP Tracking | Groups all traffic by source IP |
| 🆕 NEW Domain Flag | Highlights first-time visits per client |
| 📊 Live Web Dashboard | Beautiful real-time browser UI |
| 📁 CSV Log Export | Auto-saved log on exit |
| 🎨 Color-Coded Terminal | Easy-to-read color output |

---

## 🖥️ Preview

### Terminal Mode
```
TIME       CLIENT IP          PROTO    DOMAIN
─────────────────────────────────────────────────────────────
14:32:01   192.168.1.105      [DNS]    google.com          [NEW]
14:32:01   192.168.1.105      [DNS]    apis.google.com
14:32:02   192.168.1.88       [HTTP]   example.com → /login [NEW]
14:32:03   192.168.1.42       [DNS]    youtube.com         [NEW]
14:32:04   192.168.1.42       [DNS]    i.ytimg.com
```

### Web Dashboard
Open `http://localhost:5000` after starting dashboard mode for a live, real-time feed with client sidebar.

---

## 🚀 Installation

### Prerequisites
- Kali Linux (or any Debian-based distro)
- Python 3.8+
- Root / sudo privileges

### Step 1 — Clone the repo
```bash
git clone https://github.com/i-am-durga/saileshspy.git
cd saileshspy
```

### Step 2 — Install dependencies
```bash
pip3 install -r requirements.txt --break-system-packages
```

Or manually:
```bash
sudo apt install python3-scapy -y
pip3 install flask --break-system-packages
```

---

## 🔧 Usage

### 🖥️ Terminal Mode

```bash
# Auto-detect interface
sudo python3 saileshspy.py

# Specify interface
sudo python3 saileshspy.py -i eth0
sudo python3 saileshspy.py -i wlan0

# DNS queries only
sudo python3 saileshspy.py -i eth0 --dns-only

# HTTP requests only
sudo python3 saileshspy.py -i eth0 --http-only

# List available interfaces
sudo python3 saileshspy.py --list-interfaces
```

### 🌐 Web Dashboard Mode

```bash
sudo python3 saileshspy_dashboard.py -i eth0
```

Then open your browser → **http://localhost:5000**

Dashboard features:
- ✅ Real-time live traffic feed with animations
- ✅ Client sidebar showing all active IPs
- ✅ Click any IP to filter traffic by that client
- ✅ Packet counter, client counter, domain counter
- ✅ Auto-scrolling feed

---

## 📡 How It Works

```
Your Network
    │
    ├── Client 192.168.1.x  ── DNS query ──►
    ├── Client 192.168.1.y  ── HTTP GET ──►   Sailesh Spy (sniffing)
    └── Client 192.168.1.z  ── DNS query ──►       │
                                                    ▼
                                         Displays in plain text
                                         Groups by client IP
                                         Saves to CSV log
```

The tool runs in **promiscuous mode**, capturing packets matching:
`udp port 53` (DNS) or `tcp port 80` (HTTP)

> 📝 **Note:** HTTPS (port 443) traffic is encrypted. You will see DNS lookups for HTTPS sites but not the URL paths.

---

## 💡 Pro Tips

```bash
# Enable promiscuous mode for better packet capture
sudo ip link set eth0 promisc on

# For Wi-Fi networks — use monitor mode
sudo airmon-ng start wlan0
sudo python3 saileshspy.py -i wlan0mon

# Run on a gateway/router for full network visibility
sudo python3 saileshspy_dashboard.py -i eth0 -p 8080
```

---

## 📂 File Structure

```
saileshspy/
├── saileshspy.py            # Terminal-based sniffer
├── saileshspy_dashboard.py  # Flask web dashboard
├── requirements.txt         # Python dependencies
├── LICENSE                  # MIT License
└── README.md                # This file
```

Logs are auto-saved as: `saileshspy_YYYYMMDD_HHMMSS.log`

---

## 🛠️ Built With

- [Scapy](https://scapy.net/) — Packet capture and analysis
- [Flask](https://flask.palletsprojects.com/) — Web dashboard backend
- [Python 3](https://python.org) — Core language

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Sailesh / i-am-durga**  
- GitHub: [@i-am-durga](https://github.com/i-am-durga)

---

<p align="center">Made with ❤️ for network security learning</p>
