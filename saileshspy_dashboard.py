#!/usr/bin/env python3
"""
Sailesh Spy Dashboard — Real-time web UI for network monitoring.
Runs a Flask server so you can view live traffic from any browser.

Usage: sudo python3 saileshspy_dashboard.py -i eth0
Then open: http://localhost:5000
"""

import sys, os, json, time, threading
from datetime import datetime
from collections import defaultdict

if os.geteuid() != 0:
    print("[-] Requires root. Use: sudo python3 saileshspy_dashboard.py")
    sys.exit(1)

# Install deps
for pkg in ["flask", "scapy"]:
    try:
        __import__(pkg)
    except ImportError:
        os.system(f"pip3 install {pkg} --break-system-packages -q")

from flask import Flask, render_template_string, Response
from scapy.all import sniff, DNS, DNSQR, IP, TCP, Raw
import argparse

app = Flask(__name__)

# Shared state
events = []
clients = defaultdict(lambda: {"domains": set(), "count": 0, "last_seen": ""})
lock = threading.Lock()
MAX_EVENTS = 500

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sailesh Spy Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;800&display=swap');

  :root {
    --bg: #050a0f;
    --panel: #0a1520;
    --border: #0d3d5c;
    --accent: #00d4ff;
    --accent2: #ff4444;
    --accent3: #00ff88;
    --text: #c8e8f5;
    --dim: #3a6070;
    --glow: 0 0 12px rgba(0,212,255,0.3);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.05) 2px,
      rgba(0,0,0,0.05) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  header {
    background: linear-gradient(135deg, #020d17 0%, #0a1d30 100%);
    border-bottom: 1px solid var(--border);
    padding: 16px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 2px 20px rgba(0,212,255,0.1);
  }

  .logo {
    font-family: 'Exo 2', sans-serif;
    font-weight: 800;
    font-size: 22px;
    color: var(--accent);
    text-shadow: var(--glow);
    letter-spacing: 4px;
  }
  .logo span { color: var(--accent2); }

  .status-bar {
    display: flex; gap: 24px; align-items: center;
  }

  .stat-chip {
    background: rgba(0,212,255,0.05);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 12px;
    font-size: 11px;
    display: flex; gap: 8px; align-items: center;
  }
  .stat-chip .val {
    color: var(--accent);
    font-weight: bold;
    font-size: 14px;
  }

  .live-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent3);
    animation: pulse 1.5s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 6px var(--accent3); }
    50% { opacity: 0.3; box-shadow: none; }
  }

  .main {
    display: grid;
    grid-template-columns: 300px 1fr;
    gap: 0;
    height: calc(100vh - 65px);
  }

  /* Sidebar */
  .sidebar {
    border-right: 1px solid var(--border);
    overflow-y: auto;
    background: var(--panel);
  }
  .sidebar-title {
    padding: 12px 16px;
    font-family: 'Exo 2', sans-serif;
    font-weight: 600;
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--dim);
    border-bottom: 1px solid var(--border);
    text-transform: uppercase;
  }

  .client-card {
    border-bottom: 1px solid rgba(13,61,92,0.4);
    padding: 12px 16px;
    cursor: pointer;
    transition: background 0.15s;
  }
  .client-card:hover { background: rgba(0,212,255,0.04); }
  .client-card.active { background: rgba(0,212,255,0.08); border-left: 2px solid var(--accent); }

  .client-ip {
    color: var(--accent);
    font-weight: bold;
    font-size: 13px;
    margin-bottom: 3px;
  }
  .client-meta {
    color: var(--dim);
    font-size: 11px;
  }
  .client-count {
    display: inline-block;
    background: rgba(0,212,255,0.1);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1px 7px;
    font-size: 10px;
    color: var(--accent);
    float: right;
  }

  /* Feed */
  .feed-area {
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .feed-header {
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,0,0,0.3);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .feed-title {
    font-family: 'Exo 2', sans-serif;
    font-weight: 600;
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--dim);
    text-transform: uppercase;
  }

  #clear-btn {
    background: rgba(255,68,68,0.1);
    border: 1px solid rgba(255,68,68,0.3);
    color: var(--accent2);
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    padding: 4px 12px;
    cursor: pointer;
    border-radius: 3px;
    transition: all 0.15s;
  }
  #clear-btn:hover { background: rgba(255,68,68,0.25); }

  #feed {
    flex: 1;
    overflow-y: auto;
    padding: 8px 0;
  }

  .event {
    display: grid;
    grid-template-columns: 75px 120px 60px 1fr;
    gap: 12px;
    padding: 6px 20px;
    border-bottom: 1px solid rgba(13,61,92,0.2);
    transition: background 0.1s;
    animation: fadeIn 0.3s ease;
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateX(-8px); }
    to { opacity: 1; transform: translateX(0); }
  }
  .event:hover { background: rgba(0,212,255,0.03); }
  .event.new { background: rgba(0,255,136,0.04); }

  .ev-time { color: var(--dim); font-size: 11px; padding-top: 2px; }
  .ev-ip { color: var(--accent); font-size: 12px; }
  .ev-proto {
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 1px;
    padding: 2px 6px;
    border-radius: 3px;
    text-align: center;
    height: fit-content;
  }
  .proto-DNS { background: rgba(0,212,255,0.15); color: var(--accent); border: 1px solid rgba(0,212,255,0.3); }
  .proto-HTTP { background: rgba(0,255,136,0.12); color: var(--accent3); border: 1px solid rgba(0,255,136,0.3); }

  .ev-domain { color: #e8f4fb; word-break: break-all; }
  .ev-domain .path { color: var(--dim); font-size: 11px; }
  .ev-domain .new-badge {
    display: inline-block;
    background: var(--accent2);
    color: white;
    font-size: 9px;
    padding: 1px 5px;
    border-radius: 2px;
    margin-left: 6px;
    vertical-align: middle;
  }

  /* Column headers */
  .feed-cols {
    display: grid;
    grid-template-columns: 75px 120px 60px 1fr;
    gap: 12px;
    padding: 6px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 10px;
    letter-spacing: 1px;
    color: var(--dim);
    text-transform: uppercase;
    background: rgba(0,0,0,0.2);
  }

  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .warning-banner {
    background: rgba(255,160,0,0.08);
    border-bottom: 1px solid rgba(255,160,0,0.2);
    padding: 6px 24px;
    font-size: 11px;
    color: #ffaa00;
    text-align: center;
  }
</style>
</head>
<body>
<header>
  <div class="logo">SAILESH<span>SPY</span></div>
  <div class="status-bar">
    <div class="stat-chip"><div class="live-dot"></div> LIVE</div>
    <div class="stat-chip">PACKETS <span class="val" id="pkt-count">0</span></div>
    <div class="stat-chip">CLIENTS <span class="val" id="client-count">0</span></div>
    <div class="stat-chip">DOMAINS <span class="val" id="domain-count">0</span></div>
  </div>
</header>
<div class="warning-banner">⚠ Authorized use only — only monitor networks you own or have explicit permission to monitor</div>

<div class="main">
  <div class="sidebar">
    <div class="sidebar-title">Active Clients</div>
    <div id="clients-list"></div>
  </div>

  <div class="feed-area">
    <div class="feed-header">
      <span class="feed-title">Live Traffic Feed</span>
      <button id="clear-btn" onclick="clearFeed()">CLEAR</button>
    </div>
    <div class="feed-cols">
      <span>TIME</span><span>CLIENT IP</span><span>PROTO</span><span>DOMAIN / PATH</span>
    </div>
    <div id="feed"></div>
  </div>
</div>

<script>
let allEvents = [];
let clients = {};
let activeFilter = null;
let autoScroll = true;
let totalDomains = 0;

const feed = document.getElementById('feed');

feed.addEventListener('scroll', () => {
  const atBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 50;
  autoScroll = atBottom;
});

function clearFeed() {
  feed.innerHTML = '';
  allEvents = [];
}

function renderEvent(ev) {
  const div = document.createElement('div');
  div.className = 'event' + (ev.is_new ? ' new' : '');
  const newBadge = ev.is_new ? '<span class="new-badge">NEW</span>' : '';
  const pathHtml = ev.extra ? `<br><span class="path">→ ${ev.extra}</span>` : '';
  div.innerHTML = `
    <span class="ev-time">${ev.time}</span>
    <span class="ev-ip">${ev.ip}</span>
    <span class="ev-proto proto-${ev.proto}">${ev.proto}</span>
    <span class="ev-domain">${ev.domain}${newBadge}${pathHtml}</span>
  `;
  return div;
}

function updateClients(data) {
  const list = document.getElementById('clients-list');
  clients = data.clients;
  list.innerHTML = '';
  let totalD = 0;
  for (const [ip, info] of Object.entries(clients)) {
    totalD += info.domain_count;
    const div = document.createElement('div');
    div.className = 'client-card' + (activeFilter === ip ? ' active' : '');
    div.onclick = () => filterByIp(ip);
    div.innerHTML = `
      <span class="client-count">${info.domain_count}</span>
      <div class="client-ip">${ip}</div>
      <div class="client-meta">last: ${info.last_seen} · ${info.pkt_count} pkts</div>
    `;
    list.appendChild(div);
  }
  document.getElementById('client-count').textContent = Object.keys(clients).length;
  document.getElementById('domain-count').textContent = totalD;
  document.getElementById('pkt-count').textContent = data.total_packets;
}

function filterByIp(ip) {
  activeFilter = activeFilter === ip ? null : ip;
  refreshFeed();
}

function refreshFeed() {
  feed.innerHTML = '';
  const toShow = activeFilter
    ? allEvents.filter(e => e.ip === activeFilter)
    : allEvents;
  toShow.forEach(ev => feed.appendChild(renderEvent(ev)));
  if (autoScroll) feed.scrollTop = feed.scrollHeight;
  // update active state
  document.querySelectorAll('.client-card').forEach(el => {
    el.classList.toggle('active', el.querySelector('.client-ip').textContent === activeFilter);
  });
}

// SSE stream
const es = new EventSource('/stream');
es.onmessage = (e) => {
  const data = JSON.parse(e.data);

  if (data.type === 'event') {
    allEvents.push(data);
    if (allEvents.length > 500) allEvents.shift();
    if (!activeFilter || activeFilter === data.ip) {
      const el = renderEvent(data);
      feed.appendChild(el);
      if (autoScroll) feed.scrollTop = feed.scrollHeight;
    }
  } else if (data.type === 'stats') {
    updateClients(data);
  }
};
es.onerror = () => {
  console.log('SSE connection lost, retrying...');
};

// Poll stats every 2s
setInterval(() => {
  fetch('/stats').then(r => r.json()).then(updateClients);
}, 2000);
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/stats")
def stats():
    with lock:
        data = {
            "total_packets": len(events),
            "clients": {
                ip: {
                    "domain_count": info["count"],
                    "pkt_count": info["count"],
                    "last_seen": info["last_seen"]
                }
                for ip, info in clients.items()
            }
        }
    return json.dumps(data)

@app.route("/stream")
def stream():
    def gen():
        idx = 0
        while True:
            with lock:
                new_events = events[idx:]
                idx = len(events)
            for ev in new_events:
                yield f"data: {json.dumps(ev)}\n\n"
            time.sleep(0.3)
    return Response(gen(), mimetype="text/event-stream")

def process_packet(pkt):
    try:
        if not pkt.haslayer(IP):
            return
        src_ip = pkt[IP].src
        ts = datetime.now().strftime("%H:%M:%S")

        # DNS
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore").rstrip(".")
            if qname and "." in qname and not qname.startswith("_"):
                with lock:
                    is_new = qname not in clients[src_ip]["domains"]
                    clients[src_ip]["domains"].add(qname)
                    clients[src_ip]["count"] += 1
                    clients[src_ip]["last_seen"] = ts
                    ev = {"type": "event", "time": ts, "ip": src_ip,
                          "proto": "DNS", "domain": qname, "extra": "", "is_new": is_new}
                    events.append(ev)
                    if len(events) > MAX_EVENTS:
                        events.pop(0)

        # HTTP
        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", errors="ignore")
            if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                lines = payload.split("\r\n")
                path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"
                host = ""
                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                if host:
                    with lock:
                        is_new = host not in clients[src_ip]["domains"]
                        clients[src_ip]["domains"].add(host)
                        clients[src_ip]["count"] += 1
                        clients[src_ip]["last_seen"] = ts
                        ev = {"type": "event", "time": ts, "ip": src_ip,
                              "proto": "HTTP", "domain": host, "extra": path, "is_new": is_new}
                        events.append(ev)
                        if len(events) > MAX_EVENTS:
                            events.pop(0)
    except Exception:
        pass

def start_sniffer(iface):
    print(f"[+] Sniffing on: {iface or 'auto'}")
    sniff(
        iface=iface,
        filter="udp port 53 or tcp port 80",
        prn=process_packet,
        store=False
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sailesh Spy Web Dashboard")
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-p", "--port", type=int, default=5000)
    args = parser.parse_args()

    print("""
  Sailesh Spy Dashboard
  ─────────────────────────────────────
  ⚠  Use only on networks you own/manage
  ─────────────────────────────────────""")
    print(f"[+] Starting sniffer...")
    t = threading.Thread(target=start_sniffer, args=(args.interface,), daemon=True)
    t.start()

    print(f"[+] Dashboard → http://localhost:{args.port}")
    print(f"[+] Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=args.port, debug=False, threaded=True)
