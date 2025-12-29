#!/usr/bin/env python3
import argparse
import socket
import requests
import dns.resolver
from urllib.parse import urlparse, parse_qs

VERSION = "1.2"

# ================= BANNER =================
def banner():
    print("""
                 🦅
      __,---.___/   \\___,---.__
    /  _      _        _      _  \\
   /  / \\    / \\      / \\    / \\   \\
  |  |   |  |   |    |   |  |   |   |
   \\  \\_/    \\_/      \\_/    \\_/   /
     \\        E A G L E   R E C O N
      \\________________________________/

════════════════════════════════════════════
 Precision Recon Tool for Bug Hunters
 Author : Yusuf Abubakar
 Python3 • Termux • Kali Linux
════════════════════════════════════════════
""")

# ================= DNS =================
def run_dns(target):
    print("\n🦅 DNS Recon")
    try:
        answers = dns.resolver.resolve(target, "A")
        for rdata in answers:
            print(f"A → {rdata}")
    except:
        print("A → Not Found")

# ================= HTTP =================
def run_http(target):
    print("\n🦅 HTTP Recon")
    try:
        r = requests.get(f"http://{target}", timeout=5)
        print(f"Status → {r.status_code}")
        print(f"Server → {r.headers.get('Server')}")
    except:
        print("HTTP failed")

# ================= HEADERS =================
def run_headers(target):
    print("\n🦅 Security Headers")
    headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]
    try:
        r = requests.get(f"https://{target}", timeout=5)
        for h in headers:
            print(f"{h} → {'YES' if h in r.headers else 'NO'}")
    except:
        print("Header check failed")

# ================= PORT SCAN =================
def run_ports(target):
    print("\n🦅 Port Scan")
    for port in [80, 443, 8080]:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((target, port))
            print(f"{port} → OPEN")
        except:
            print(f"{port} → CLOSED")
        s.close()

# ================= XSS (BASIC) =================
def run_xss(target):
    print("\n🦅 Reflected XSS (Basic)")
    payload = "<xss>"
    test_url = f"http://{target}/?q={payload}"
    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            print(f"[VULN] Reflected XSS → {test_url}")
        else:
            print("XSS test failed")
    except:
        print("XSS check error")

# ================= SUBDOMAINS =================
def run_subs(target):
    print("\n🦅 Subdomain Enumeration")
    subs = ["www", "mail", "ftp", "dev", "test"]
    found = 0
    for sub in subs:
        host = f"{sub}.{target}"
        try:
            socket.gethostbyname(host)
            print(host)
            found += 1
        except:
            pass
    print(f"\nTotal: {found} subdomains")

# ================= MAIN =================
def main():
    parser = argparse.ArgumentParser(
        description="EagleRecon - Modular Recon Tool"
    )
    parser.add_argument("target", help="Target domain")
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--http", action="store_true")
    parser.add_argument("--headers", action="store_true")
    parser.add_argument("--ports", action="store_true")
    parser.add_argument("--xss", action="store_true")
    parser.add_argument("--subs", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("-v", "--version", action="version", version=VERSION)

    args = parser.parse_args()
    banner()
    print(f"\n🎯 Target: {args.target}")

    if args.all:
        run_dns(args.target)
        run_http(args.target)
        run_headers(args.target)
        run_ports(args.target)
        run_xss(args.target)
        run_subs(args.target)
        return

    ran = False
    if args.dns: run_dns(args.target); ran = True
    if args.http: run_http(args.target); ran = True
    if args.headers: run_headers(args.target); ran = True
    if args.ports: run_ports(args.target); ran = True
    if args.xss: run_xss(args.target); ran = True
    if args.subs: run_subs(args.target); ran = True

    if not ran:
        print("\n[!] No option selected. Use -h")

if __name__ == "__main__":
    main()
