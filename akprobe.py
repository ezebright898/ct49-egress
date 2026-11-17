#!/usr/bin/env python3
"""ct49 authentik reachability probe (read-only GET) from a GitHub-hosted runner."""
import json
import ssl
import time
import urllib.request
import urllib.error

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
CTX = ssl.create_default_context()
TARGETS = [
    ("authentik-rootcfg", "https://authentik.api.cardtonic.com/api/v3/root/config/"),
    ("authentik-healthlive", "https://authentik.api.cardtonic.com/-/health/live/"),
    ("authentik-usersme", "https://authentik.api.cardtonic.com/api/v3/core/users/me/"),
    ("vault-control", "https://vault.api.cardtonic.com/v1/sys/health"),
]
out = []


def get(name, url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            body = r.read(1500)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            rec = {"name": name, "url": url, "status": r.status, "len_hdr": r.headers.get("content-length"),
                   "server": hdrs.get("server"), "cf_ray": hdrs.get("cf-ray"),
                   "content_type": hdrs.get("content-type"),
                   "set_cookie": hdrs.get("set-cookie"),
                   "body_head": body[:200].decode("utf-8", "replace"),
                   "elapsed": round(time.time() - t0, 2)}
    except urllib.error.HTTPError as e:
        body = e.read(1500)
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        rec = {"name": name, "url": url, "status": e.code, "len_hdr": e.headers.get("content-length"),
               "server": hdrs.get("server"), "cf_ray": hdrs.get("cf-ray"),
               "content_type": hdrs.get("content-type"),
               "set_cookie": hdrs.get("set-cookie"),
               "body_head": body[:200].decode("utf-8", "replace"),
               "elapsed": round(time.time() - t0, 2)}
    except Exception as e:  # noqa
        rec = {"name": name, "url": url, "status": None, "error": repr(e)[:200],
               "elapsed": round(time.time() - t0, 2)}
    out.append(rec)
    print(json.dumps(rec, ensure_ascii=False))


# egress IP of this runner (two independent services, first one that answers)
for ipurl in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
    try:
        with urllib.request.urlopen(urllib.request.Request(ipurl, headers={"User-Agent": "curl/8.5.0"}),
                                    timeout=15, context=CTX) as r:
            ip = r.read(100).decode().strip()
        print(json.dumps({"egress_ip": ip, "via": ipurl}))
        out.append({"egress_ip": ip, "via": ipurl})
        break
    except Exception as e:  # noqa
        print(json.dumps({"egress_ip_error": repr(e)[:120], "via": ipurl}))

for n, u in TARGETS:
    get(n, u)
    time.sleep(1)

with open("out2/summary.txt", "w") as f:
    f.write(json.dumps(out, ensure_ascii=False, indent=1))
