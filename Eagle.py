#!/usr/bin/env python3
import argparse, socket, requests, dns.resolver, whois, json
from prettytable import PrettyTable
from colorama import Fore, Style, init

init(autoreset=True)

# ================== BANNER ==================
BANNER = f"""{Fore.CYAN}
                 🦅
                / \\
      __,---.___/   \\___,---.__
    /  _      _        _      _  \\
   /  / \\    / \\      / \\    / \\   \\
  |  |   |  |   |    |   |  |   |   |
   \\  \\_/    \\_/      \\_/    \\_/   /
    \\
     \\        E A G L E   R E C O N
      \\________________________________/

════════════════════════════════════════════
 Precision Recon Tool for Bug Hunters
      Authoriz : Yusuf Abubakar 
           Ethical Hacker
════════════════════════════════════════════
{Style.RESET_ALL}
"""

# ================== CONFIG ==================
PORTS = [21,22,25,53,80,110,143,443,445,587,8080,8443,3306,3389,5900]

AUTO_STOP = True

RESULTS = {
    "target": "",
    "dns": [],
    "ports": [],
    "whois": {},
    "fingerprint": {},
    "cookies": [],
    "subdomains": []
}
# ================== HELPERS ==================
def table(headers):
    t = PrettyTable([Fore.CYAN + h + Style.RESET_ALL for h in headers])
    t.align = "l"
    return t

def section(name):
    print(f"\n{Fore.YELLOW}🦅 {name}{Style.RESET_ALL}")

def resolver_fix():
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    return r

# ================== MODULES ==================
def dns_recon(domain):
    section("DNS Recon")
    t = table(["Record","Value"])
    for rec in ["A","AAAA","MX","NS"]:
        try:
            for a in resolver_fix().resolve(domain, rec):
                t.add_row([rec, Fore.GREEN + str(a)])
        except:
            t.add_row([rec, Fore.WHITE + "Not Found"])
    print(t)

def port_scan(domain):
    section("Port Scan")
    t = table(["Port","Status"])
    for p in PORTS:
        try:
            s = socket.socket()
            s.settimeout(0.7)
            s.connect((domain,p))
            t.add_row([p, Fore.GREEN + "OPEN"])
            s.close()
        except:
            t.add_row([p, Fore.WHITE + "CLOSED"])
    print(t)

def whois_info(domain):
    section("WHOIS")
    t = table(["Field", "Value"])

    try:
        w = whois.whois(domain)

        def clean(v):
            if isinstance(v, list):
                return ", ".join(str(x) for x in v if x)
            return str(v) if v else "N/A"

        rows = {
            "Domain": clean(w.domain_name),
            "Registrar": clean(w.registrar),
            "Created": clean(w.creation_date),
            "Expires": clean(w.expiration_date),
            "Updated": clean(w.updated_date),
            "Country": clean(w.country),
            "Org": clean(w.org),
            "Name Servers": clean(w.name_servers),
        }

        for k, v in rows.items():
            t.add_row([Fore.YELLOW + k, Fore.WHITE + v])

    except Exception as e:
        t.add_row([Fore.RED + "Error", Fore.WHITE + str(e)])

    print(t)

def fingerprint(domain):
    section("Fingerprint")
    t = table(["Header", "Value"])
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        for h in ["Server", "X-Powered-By", "Content-Type"]:
            val = r.headers.get(h, "Unknown")
            color = Fore.GREEN if val != "Unknown" else Fore.WHITE
            t.add_row([Fore.YELLOW + h, color + val])
    except:
        t.add_row(["Error", Fore.RED + "Failed"])
    print(t)

def cookies(domain):
    section("Cookies")
    t = table(["Name","Secure","HttpOnly"])
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        for c in r.cookies:
            t.add_row([
                Fore.WHITE + c.name,
                Fore.GREEN + "Yes" if c.secure else Fore.WHITE + "No",
                Fore.GREEN + "Yes" if "httponly" in c._rest else Fore.WHITE + "No"
            ])
    except:
        t.add_row(["Error","-","-"])
    print(t)

def subdomains(domain):
    section("Subdomains")
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        for e in r.json():
            for s in e["name_value"].split("\n"):
                if s.endswith(domain):
                    subs.add(s.strip())
    except:
        pass

    for s in sorted(subs):
        print(Fore.GREEN + s)
    print(Fore.CYAN + f"\nTotal: {len(subs)}")

# ================== MAIN ==================
def main():
    print(BANNER)

    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--dns", action="store_true")
    ap.add_argument("--port", action="store_true")
    ap.add_argument("--whois", action="store_true")
    ap.add_argument("--fingerprint", action="store_true")
    ap.add_argument("--cookies", action="store_true")
    ap.add_argument("--subdomains", action="store_true")
    args = ap.parse_args()

    domain = args.target.replace("http://","").replace("https://","")
    print(f"{Fore.CYAN}🎯 Target: {domain}")

    if args.all or args.dns: dns_recon(domain)
    if args.all or args.port: port_scan(domain)
    if args.all or args.whois: whois_info(domain)
    if args.all or args.fingerprint: fingerprint(domain)
    if args.all or args.cookies: cookies(domain)
    if args.all or args.subdomains: subdomains(domain)

if __name__ == "__main__":
    main()
