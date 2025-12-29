#!/usr/bin/env python3
import argparse, requests, dns.resolver, whois, socket
from rich.console import Console
from rich.table import Table

console = Console()

# ================= BANNER =================
def banner():
    console.print(r"""
[bold yellow]
                 🦅
                / \\
      __,---.___/   \___,---.__
    /  _      _        _      _  \
   /  / \    / \      / \    / \   \
  |  |   |  |   |    |   |  |   |   |
   \  \_/    \_/      \_/    \_/   /
    \
     \        E A G L E   R E C O N
      \________________________________/
[/bold yellow]

[bold green]
════════════════════════════════════════════
 Precision Recon Tool for Bug Hunters
 Author : Yusuf Abubakar
 Python3 • Termux • Kali Linux
════════════════════════════════════════════
[/bold green]
""")

# ================= DNS =================
def dns_recon(domain):
    t = Table(title="🦅 DNS Recon", header_style="bold green")
    t.add_column("Record", style="cyan")
    t.add_column("Value", style="white")
    try:
        for r in dns.resolver.resolve(domain, "A"):
            t.add_row("A", r.to_text())
    except:
        t.add_row("A", "Not Found")
    console.print(t)

# ================= WHOIS =================
def whois_recon(domain):
    t = Table(title="🦅 WHOIS", header_style="bold green")
    t.add_column("Field", style="cyan")
    t.add_column("Value", style="white")
    try:
        w = whois.whois(domain)
        for k, v in w.items():
            t.add_row(str(k), str(v))
    except:
        t.add_row("Error", "WHOIS failed")
    console.print(t)

# ================= HTTP =================
def http_recon(domain):
    t = Table(title="🦅 HTTP Recon", header_style="bold green")
    t.add_column("Item", style="cyan")
    t.add_column("Value", style="white")
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        t.add_row("Final URL", r.url)
        t.add_row("Status Code", str(r.status_code))
        t.add_row("Server", r.headers.get("Server", "N/A"))
    except:
        t.add_row("Error", "HTTP failed")
    console.print(t)

# ================= HEADERS =================
def security_headers(domain):
    headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]
    t = Table(title="🦅 Security Headers", header_style="bold green")
    t.add_column("Header", style="cyan")
    t.add_column("Present", style="white")
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        for h in headers:
            t.add_row(h, "[green]YES[/green]" if h in r.headers else "[red]NO[/red]")
    except:
        t.add_row("Error", "Failed")
    console.print(t)

# ================= COOKIES =================
def cookies(domain):
    t = Table(title="🦅 Cookies", header_style="bold green")
    t.add_column("Name", style="cyan")
    t.add_column("Secure")
    t.add_column("HttpOnly")
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        for c in r.cookies:
            t.add_row(
                c.name,
                "[green]True[/green]" if c.secure else "[red]False[/red]",
                "[green]True[/green]" if c.has_nonstandard_attr("HttpOnly") else "[red]False[/red]"
            )
    except:
        t.add_row("Error", "-", "-")
    console.print(t)

# ================= FINGERPRINT =================
def fingerprint(domain):
    t = Table(title="🦅 Technology Fingerprint", header_style="bold green")
    t.add_column("Header", style="cyan")
    t.add_column("Value", style="white")
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        for h in ["Server", "X-Powered-By"]:
            if h in r.headers:
                t.add_row(h, r.headers[h])
    except:
        t.add_row("Error", "Failed")
    console.print(t)

# ================= PORT SCAN =================
def port_scan(domain):
    t = Table(title="🦅 Port Scan", header_style="bold green")
    t.add_column("Port", style="cyan")
    t.add_column("Status", style="white")
    for p in [80, 443, 8080]:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((domain, p))
            t.add_row(str(p), "[green]OPEN[/green]")
            s.close()
        except:
            t.add_row(str(p), "[red]CLOSED[/red]")
    console.print(t)

# ================= XSS (BASIC) =================
def reflected_xss(domain):
    console.print("\n[bold green]🦅 Reflected XSS (Basic)[/bold green]\n")
    payload = "<script>alert(1)</script>"
    try:
        url = f"https://{domain}/?xss={payload}"
        r = requests.get(url, timeout=10)
        if payload in r.text:
            console.print("[bold red]Possible Reflected XSS Found![/bold red]")
        else:
            console.print("[yellow]XSS test finished (no reflection)[/yellow]")
    except:
        console.print("[red]XSS test failed[/red]")

# ================= SUBDOMAINS (FULL) =================
def subdomains(domain):
    console.print("\n[bold green]🦅 Subdomain Enumeration[/bold green]\n")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        subs = set()
        for e in r.json():
            for s in e.get("name_value","").split("\n"):
                s = s.strip()
                if s.endswith(domain):
                    subs.add(s)
        for s in sorted(subs):
            console.print(f"[green]{s}[/green]")
        console.print(f"\n[bold yellow]Total:[/] [bold cyan]{len(subs)}[/bold cyan]\n")
    except:
        console.print("[bold red]Subdomain enumeration failed[/bold red]")

# ================= MAIN =================
def main():
    p = argparse.ArgumentParser(description="Eagle Recon")
    p.add_argument("target")
    p.add_argument("--all", action="store_true")
    p.add_argument("--dns", action="store_true")
    p.add_argument("--whois", action="store_true")
    p.add_argument("--http", action="store_true")
    p.add_argument("--headers", action="store_true")
    p.add_argument("--cookies", action="store_true")
    p.add_argument("--fingerprint", action="store_true")
    p.add_argument("--port", action="store_true")
    p.add_argument("--xss", action="store_true")
    p.add_argument("--subs", action="store_true")
    a = p.parse_args()

    banner()
    console.print(f"[bold yellow]🎯 Target:[/] {a.target}\n")

    if a.all or a.dns: dns_recon(a.target)
    if a.all or a.whois: whois_recon(a.target)
    if a.all or a.http: http_recon(a.target)
    if a.all or a.headers: security_headers(a.target)
    if a.all or a.cookies: cookies(a.target)
    if a.all or a.fingerprint: fingerprint(a.target)
    if a.all or a.port: port_scan(a.target)
    if a.all or a.xss: reflected_xss(a.target)
    if a.all or a.subs: subdomains(a.target)

if __name__ == "__main__":
    main()
