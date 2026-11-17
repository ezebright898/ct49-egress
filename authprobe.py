#!/usr/bin/env python3
# ct49 authprobe: runner-vantage (Azure egress) vs sandbox comparison for CF-fronted
# authentik/toniks/harbor/vault hosts. Read-only GETs. Runs on GitHub-hosted runner.
import hashlib
import json
import os
import socket
import ssl
import sys
import time
import urllib.request

OUT = "out2"
os.makedirs(OUT, exist_ok=True)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

TARGETS = [
    ("authentik.api.root",    "https://authentik.api.cardtonic.com/"),
    ("authentik.api.config",  "https://authentik.api.cardtonic.com/api/v3/root/config/"),
    ("authentik.api.health",  "https://authentik.api.cardtonic.com/-/health/live/"),
    ("authentik.apex",        "https://authentik.cardtonic.com/"),
    ("authentik.staging",     "https://authentik.staging.cardtonic.com/"),
    ("toniks.root",           "https://toniks.cardtonic.com/"),
    ("harbor.systeminfo",     "https://harbor.cardtonic.com/api/v2.0/systeminfo"),
    ("vault.health",          "https://vault.api.cardtonic.com/v1/sys/health"),
]
HDR_KEYS = ("server", "cf-ray", "cf-cache-status", "cf-mitigated", "content-type",
            "location", "set-cookie", "www-authenticate", "retry-after", "x-frame-options")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def dns(host):
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        ips = []
        for i in infos:
            a = i[4][0]
            if a not in ips:
                ips.append(a)
        return ips
    except Exception as e:
        return ["ERR:%s" % type(e).__name__]


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    t0 = time.time()
    try:
        r = opener.open(req, timeout=timeout)
        body = r.read(400000)
        status, hdrs = r.getcode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read(400000)
        status, hdrs = e.code, dict(e.headers)
    except Exception as e:
        return {"url": url, "error": "%s: %s" % (type(e).__name__, str(e)[:160]),
                "elapsed_ms": int((time.time() - t0) * 1000)}
    out = {"url": url, "status": status, "bytes": len(body),
           "md5": hashlib.md5(body).hexdigest(),
           "elapsed_ms": int((time.time() - t0) * 1000),
           "body_head": body[:400].decode("utf-8", "replace"),
           "headers": {k: hdrs.get(k, "") for k in HDR_KEYS if hdrs.get(k)}}
    return out, body


results = []
bodies = {}
for name, url in TARGETS:
    host = url.split("/")[2]
    r = fetch(url)
    rec, body = (r if isinstance(r, tuple) else (r, b""))
    rec["name"] = name
    rec["dns"] = dns(host)
    rec["cf_blocked"] = ("Sorry, you have been blocked" in rec.get("body_head", "")
                         or "Attention Required" in rec.get("body_head", ""))
    results.append(rec)
    bodies[name] = body
    print("[%s] %s -> %s %sB md5=%s dns=%s blocked=%s" % (
        name, url, rec.get("status", rec.get("error")), rec.get("bytes"),
        rec.get("md5", "-"), ",".join(rec.get("dns", [])), rec.get("cf_blocked")))
    for b in rec.get("dns", []):
        pass
    if body:
        with open(os.path.join(OUT, name + ".body"), "wb") as f:
            f.write(body[:400000])
    time.sleep(0.6)

egress_ip = None
try:
    r = fetch("https://api.ipify.org?format=text")
    rec, body = (r if isinstance(r, tuple) else (r, b""))
    egress_ip = body.decode("latin1", "replace").strip()[:64]
    print("egress_ip=%s" % egress_ip)
except Exception as e:
    print("egress_ip error %s" % e)

with open(os.path.join(OUT, "compare.json"), "w") as f:
    json.dump({"egress_ip": egress_ip, "results": results}, f, indent=2)

# ---------- stage B: only if authentik itself is reachable ----------
auth_recs = [r for r in results if r["name"].startswith("authentik") and not r.get("error")]
reachable = [r for r in auth_recs if r.get("status") in (200, 301, 302, 303, 307, 308, 401, 400)
             and not r.get("cf_blocked")]
stage_b = {"reachable": bool(reachable), "probes": []}
print("\n== stage B: authentik reachable = %s ==" % bool(reachable))
if reachable:
    # pick the host that answered
    base = None
    for r in reachable:
        if r["name"] in ("authentik.api.root", "authentik.apex", "authentik.staging"):
            base = "https://" + r["url"].split("/")[2]
            break
    if base:
        stage_b["base"] = base
        extra = [
            ("root.config", base + "/api/v3/root/config/"),
            ("health.live", base + "/-/health/live/"),
            ("flows.auth.executor", base + "/api/v3/flows/executor/default-authentication-flow/?query="),
            ("flows.enroll.executor", base + "/api/v3/flows/executor/default-enrollment-flow/?query="),
            ("outpost.start", base + "/outpost.goauthentik.io/start?rd=/"),
        ]
        for name, url in extra:
            r = fetch(url)
            rec, body = (r if isinstance(r, tuple) else (r, b""))
            rec["name"] = name
            stage_b["probes"].append(rec)
            print("[B:%s] %s -> %s %sB" % (name, url, rec.get("status", rec.get("error")),
                                           rec.get("bytes")))
            if body:
                with open(os.path.join(OUT, "b_" + name + ".body"), "wb") as f:
                    f.write(body[:200000])
            time.sleep(0.6)
        # toniks SSO: follow with a cookie jar and see where it lands
        try:
            import http.cookiejar
            cj = http.cookiejar.CookieJar()
            op2 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                              urllib.request.HTTPSHandler(context=ctx))

            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            op3 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                              urllib.request.HTTPSHandler(context=ctx), NoRedir())
            try:
                r = op3.open(urllib.request.Request("https://toniks.cardtonic.com/",
                                                    headers={"User-Agent": UA}), timeout=25)
                st, hd = r.getcode(), dict(r.headers)
            except urllib.error.HTTPError as e:
                st, hd = e.code, dict(e.headers)
            loc = hd.get("Location", "")
            stage_b["toniks_start"] = {"status": st, "location": loc[:400]}
            print("[B:toniks] %s -> %s loc=%s" % ("https://toniks.cardtonic.com/", st, loc[:160]))
        except Exception as e:
            stage_b["toniks_start"] = {"error": str(e)[:160]}

with open(os.path.join(OUT, "stageb.json"), "w") as f:
    json.dump(stage_b, f, indent=2)

# summary table (also printed to job summary by workflow)
lines = []
for r in results:
    lines.append("%-20s %-6s %-7s %-10s %s" % (
        r["name"], r.get("status", "-"), r.get("bytes", "-"),
        ",".join(r.get("dns", []))[:60],
        (r.get("body_head", "") or r.get("error", ""))[:100].replace("\n", " ")))
with open(os.path.join(OUT, "summary.txt"), "w") as f:
    f.write("\n".join(lines))
print("\n".join(lines))
print("\nDONE")
