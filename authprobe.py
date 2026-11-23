#!/usr/bin/env python3
# ct49 egress49 v2 — Azure runner vantage: extra IP sample + CF 1020 confirmation + raw TCP to source hosts
import json, socket, time, traceback
import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
H = {"User-Agent": UA, "Accept": "*/*"}

def p(*a):
    print(*a, flush=True)

def probe(url, nbytes=160):
    try:
        r = requests.get(url, headers=H, timeout=15, allow_redirects=False)
        b = r.content
        txt = b.decode("utf-8", "replace")
        mark = ""
        for kw in ("error code: 1020", "1020", "Attention Required", "Forbidden", "just a moment"):
            if kw.lower() in txt.lower():
                mark += "|KW=" + kw
                break
        if r.status_code == 403:
            p("PROBE|%s|%s|len=%d|cf-ray=%s%s|first=%s" % (
                url, r.status_code, len(b), r.headers.get("cf-ray", "-"), mark,
                txt[:nbytes].replace("\n", "\\n").replace("\r", "")))
        elif r.status_code == 200:
            p("PROBE|%s|200|len=%d|ct=%s|first=%s" % (url, len(b), r.headers.get("content-type", "-"), txt[:nbytes]))
        else:
            p("PROBE|%s|%s|len=%d|cf-ray=%s|first=%s" % (url, r.status_code, len(b), r.headers.get("cf-ray", "-"), txt[:nbytes]))
    except Exception as e:
        p("PROBE|%s|ERR|%r" % (url, repr(e)[:160]))

def rawsock(host, port, send=None, timeout=6.0):
    t = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        out = ""
        if send:
            s.sendall(send.encode())
            try:
                out = s.recv(600).decode("utf-8", "replace").replace("\r", "\\r").replace("\n", "\\n")
            except socket.timeout:
                out = "<recv timeout>"
        s.close()
        p("TCP|%s:%d|OPEN|%.2fs|resp=%s" % (host, port, time.time() - t, out[:400]))
    except Exception as e:
        p("TCP|%s:%d|ERR|%.2fs|%r" % (host, port, time.time() - t, repr(e)[:120]))

def main():
    p("### RUNNER EGRESS IP SAMPLE ###")
    for u in ("https://ifconfig.me/ip", "https://api.ipify.org", "https://ipinfo.io/ip"):
        try:
            r = requests.get(u, headers=H, timeout=12)
            p("IP|%s|%s" % (u, r.text.strip()[:80]))
        except Exception as e:
            p("IP|%s|ERR|%r" % (u, repr(e)[:100]))
        time.sleep(0.3)

    p("### PHASE A2: *.api CF WAF re-check from this runner ###")
    for u in ("https://authentik.api.cardtonic.com/-/health/live/",
              "https://authentik.api.cardtonic.com/api/v3/root/config/",
              "https://grafana.api.cardtonic.com/api/health",
              "https://prometheus.api.cardtonic.com/api/v1/targets",
              "https://vault.api.cardtonic.com/v1/sys/health"):
        probe(u)
        time.sleep(0.4)

    p("### PHASE B2: raw TCP (no transparent proxy on Azure) ###")
    rawsock("129.212.142.60", 80, "GET / HTTP/1.0\r\nHost: toniks.cardtonic.com\r\n\r\n")
    time.sleep(0.3)
    rawsock("129.212.142.60", 8080, "GET /api/rawdata HTTP/1.1\r\nHost: jobs.api.pil.com\r\nConnection: close\r\n\r\n")
    time.sleep(0.3)
    rawsock("129.212.142.60", 8443)
    time.sleep(0.3)
    rawsock("129.212.142.60", 50070, "GET /webhdfs/v1/?op=LISTSTATUS HTTP/1.0\r\nHost: 129.212.142.60\r\n\r\n")
    time.sleep(0.3)
    rawsock("129.212.194.148", 443)
    time.sleep(0.3)
    rawsock("129.212.194.148", 80, "GET / HTTP/1.0\r\nHost: 129.212.194.148\r\n\r\n")
    time.sleep(0.3)
    rawsock("142.93.160.150", 5678, "GET /healthz HTTP/1.0\r\nHost: 142.93.160.150\r\n\r\n")
    p("### DONE2 ###")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        p("FATAL|" + traceback.format_exc()[:1500])
