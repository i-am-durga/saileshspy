#!/usr/bin/env python3
"""
Sailesh Spy - Network Traffic Analyzer for Kali Linux
Monitors DNS queries and HTTP requests to show which websites
clients on your network are visiting.

⚠️  LEGAL NOTICE: Only use on networks you own or have explicit
    written permission to monitor. Unauthorized interception of
    network traffic is illegal in most jurisdictions.
"""

import sys
import os
import time
import signal
import argparse
import threading
from datetime import datetime
from collections import defaultdict

# Check root
if os.geteuid() != 0:
    print("[-] This tool requires root privileges. Run with sudo.")
    sys.exit(1)

try:
    from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP, Raw, conf
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("[-] Scapy not found. Installing...")
    os.system("pip3 install scapy --break-system-packages -q")
    from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP, Raw, conf

# ── Colors ─────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
    BG_RED = "\033[41m"

# ── Global state ───────────────────────────────────────────────────────────────
seen = defaultdict(set)          # ip -> set of domains
log_entries = []
running = True
lock = threading.Lock()
pkt_count = 0
start_time = time.time()

BANNER = f"""
{C.BOLD}{C.CYAN}
 ███████╗ █████╗ ██╗██╗     ███████╗███████╗██╗  ██╗
 ██╔════╝██╔══██╗██║██║     ██╔════╝██╔════╝██║  ██║
 ███████╗███████║██║██║     █████╗  ███████╗███████║
 ╚════██║██╔══██║██║██║     ██╔══╝  ╚════██║██╔══██║
 ███████║██║  ██║██║███████╗███████╗███████║██║  ██║
 ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{C.RESET}{C.BOLD}{C.RED}
 ███████╗██████╗ ██╗   ██╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝
 ███████╗██████╔╝ ╚████╔╝ 
 ╚════██║██╔═══╝   ╚██╔╝  
 ███████║██║        ██║   
 ╚══════╝╚═╝        ╚═╝   
{C.RESET}{C.DIM} Network Traffic Analyzer — DNS & HTTP Inspector{C.RESET}
{C.YELLOW} ⚠  Authorized use only — monitor only your own network{C.RESET}
"""

def print_banner():
    print(BANNER)

def format_time():
    return datetime.now().strftime("%H:%M:%S")

def log(ip, proto, domain, extra=""):
    global pkt_count
    with lock:
        pkt_count += 1
        ts = format_time()
        is_new = domain not in seen[ip]
        seen[ip].add(domain)

        # Color coding
        if proto == "DNS":
            proto_color = C.CYAN
        elif proto == "HTTP":
            proto_color = C.GREEN
        else:
            proto_color = C.YELLOW

        new_tag = f" {C.BOLD}{C.RED}[NEW]{C.RESET}" if is_new else ""
        extra_str = f" {C.DIM}→ {extra}{C.RESET}" if extra else ""

        line = (
            f"{C.DIM}{ts}{C.RESET} "
            f"{C.BOLD}{C.WHITE}{ip:<16}{C.RESET} "
            f"{proto_color}[{proto}]{C.RESET} "
            f"{C.YELLOW}{domain}{C.RESET}"
            f"{extra_str}{new_tag}"
        )
        print(line)

        entry = {"time": ts, "ip": ip, "proto": proto, "domain": domain, "extra": extra}
        log_entries.append(entry)

def process_packet(pkt):
    """Extract DNS queries and HTTP Host headers from packets."""
    try:
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src

        # ── DNS Query ──────────────────────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore").rstrip(".")
            if qname and not qname.startswith("_") and "." in qname:
                log(src_ip, "DNS", qname)

        # ── HTTP (port 80) ─────────────────────────────────────────────────
        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", errors="ignore")

            if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                lines = payload.split("\r\n")
                method_line = lines[0]
                host = ""
                path = ""

                # Extract method + path
                parts = method_line.split(" ")
                if len(parts) >= 2:
                    path = parts[1]

                # Extract Host header
                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break

                if host:
                    full = host + (path if path != "/" else "")
                    log(src_ip, "HTTP", host, path)

    except Exception:
        pass

def stats_printer():
    """Print a live stats line every 10 seconds."""
    while running:
        time.sleep(10)
        if not running:
            break
        elapsed = int(time.time() - start_time)
        unique_hosts = len(seen)
        total_domains = sum(len(v) for v in seen.values())
        print(
            f"\n{C.DIM}── Stats: {pkt_count} packets | "
            f"{unique_hosts} clients | "
            f"{total_domains} unique domains | "
            f"{elapsed}s elapsed ──{C.RESET}\n"
        )

def print_summary():
    """Print final summary when stopping."""
    print(f"\n{C.BOLD}{C.CYAN}{'═'*60}")
    print("  CAPTURE SUMMARY")
    print(f"{'═'*60}{C.RESET}")
    print(f"  {C.WHITE}Total packets analyzed : {C.YELLOW}{pkt_count}{C.RESET}")
    print(f"  {C.WHITE}Unique clients         : {C.YELLOW}{len(seen)}{C.RESET}")
    print(f"  {C.WHITE}Duration               : {C.YELLOW}{int(time.time()-start_time)}s{C.RESET}")
    print()

    for ip, domains in sorted(seen.items()):
        print(f"  {C.BOLD}{C.CYAN}{ip}{C.RESET}")
        for d in sorted(domains):
            print(f"    {C.DIM}└─{C.RESET} {C.WHITE}{d}{C.RESET}")
        print()

    # Save log
    if log_entries:
        logfile = f"saileshspy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        with open(logfile, "w") as f:
            f.write("time,src_ip,protocol,domain,extra\n")
            for e in log_entries:
                f.write(f"{e['time']},{e['ip']},{e['proto']},{e['domain']},{e['extra']}\n")
        print(f"  {C.GREEN}[+] Log saved → {logfile}{C.RESET}\n")

def get_interfaces():
    """List available network interfaces."""
    from scapy.all import get_if_list
    return get_if_list()

def signal_handler(sig, frame):
    global running
    running = False
    print(f"\n{C.YELLOW}[!] Stopping capture...{C.RESET}")
    print_summary()
    sys.exit(0)

def main():
    global running

    parser = argparse.ArgumentParser(
        description="Sailesh Spy — Network DNS & HTTP Traffic Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  sudo python3 saileshspy.py -i eth0\n"
               "  sudo python3 saileshspy.py -i wlan0 --filter '192.168.1.0/24'\n"
               "  sudo python3 saileshspy.py --list-interfaces"
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to listen on (default: auto)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available interfaces and exit")
    parser.add_argument("--dns-only", action="store_true",
                        help="Capture DNS queries only")
    parser.add_argument("--http-only", action="store_true",
                        help="Capture HTTP requests only")
    parser.add_argument("--no-stats", action="store_true",
                        help="Disable periodic stats output")
    args = parser.parse_args()

    if args.list_interfaces:
        ifaces = get_interfaces()
        print(f"\n{C.BOLD}Available interfaces:{C.RESET}")
        for i in ifaces:
            print(f"  {C.CYAN}• {i}{C.RESET}")
        print()
        sys.exit(0)

    print_banner()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Build BPF filter
    if args.dns_only:
        bpf = "udp port 53"
    elif args.http_only:
        bpf = "tcp port 80"
    else:
        bpf = "udp port 53 or tcp port 80"

    iface = args.interface
    if iface:
        print(f"{C.GREEN}[+] Interface : {C.WHITE}{iface}{C.RESET}")
    else:
        print(f"{C.GREEN}[+] Interface : {C.WHITE}auto-detect{C.RESET}")
    print(f"{C.GREEN}[+] Filter    : {C.WHITE}{bpf}{C.RESET}")
    print(f"{C.GREEN}[+] Capturing : {C.WHITE}DNS queries + HTTP requests{C.RESET}")
    print(f"{C.DIM}{'─'*60}{C.RESET}")
    print(f"{'TIME':<10} {'CLIENT IP':<18} {'PROTO':<8} DOMAIN / URL")
    print(f"{C.DIM}{'─'*60}{C.RESET}\n")

    # Start stats thread
    if not args.no_stats:
        t = threading.Thread(target=stats_printer, daemon=True)
        t.start()

    # Start sniffing
    try:
        sniff(
            iface=iface,
            filter=bpf,
            prn=process_packet,
            store=False
        )
    except PermissionError:
        print(f"{C.RED}[-] Permission denied. Run with sudo.{C.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{C.RED}[-] Error: {e}{C.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
