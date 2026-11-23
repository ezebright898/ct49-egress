#!/usr/bin/env python3
# ct49 full 1-65535 TCP port map -- runs on GitHub-hosted runner (Azure egress, real stack).
# Read-only: nmap SYN connect scan + service/banner version detection + tiny HTTP GET/raw banner.
# Targets: the 4 in-scope cardtonic hosts only.
import subprocess, sys, os, json, time, socket, re
import xml.etree.ElementTree as ET

IPS = ["142.93.160.150", "129.212.142.60", "129.212.194.148", "139.59.131.46"]
OUT = "out2"
os.makedirs(OUT, exist_ok=True)

def p(*a):
    print(*a, flush=True)

def sh(cmd, timeout=1300):
    t = time.time()
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"), time.time() - t
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT", time.time() - t

def egress():
    for u in ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]:
        rc, o, e, dt = sh("curl -s -m 10 %s" % u, 30)
        if o.strip() and len(o.strip()) < 64:
            return o.strip()

def ensure_nmap():
    rc, o, e, dt = sh("command -v nmap && nmap --version | head -1", 30)
    if rc != 0 or "Nmap version" not in o:
        p("installing nmap ...")
        sh("sudo apt-get update -qq", 300)
        rc, o, e, dt = sh("sudo apt-get -y install nmap", 300)
        p("apt install rc=%s tail=%s" % (rc, e.strip()[-200:]))
    rc, o, e, dt = sh("nmap --version | head -1", 30)
    p("NMAP %s" % o.strip())

def scan(ip):
    safe = ip.replace(".", "_")
    xml = os.path.join(OUT, "scan_%s.xml" % safe)
    gnmap = os.path.join(OUT, "scan_%s.gnmap" % safe)
    cmd = ("sudo nmap -Pn -sS -p- -T4 --min-rate 2000 --max-retries 1 "
           "--host-timeout 420s --defeat-rst-ratelimit "
           "-oX %s -oG %s %s" % (xml, gnmap, ip))
    p("### SCAN %s : %s" % (ip, cmd))
    rc, o, e, dt = sh(cmd, 700)
    p("scan rc=%s dt=%.1fs stderr_tail=%s" % (rc, dt, e.strip()[-300:]))
    opens = []
    counts = {"open": 0, "closed": 0, "filtered": 0, "open|filtered": 0, "other": 0}
    try:
        tree = ET.parse(xml)
        for port in tree.getroot().iter("port"):
            st = port.find("state").get("state")
            pnum = int(port.get("portid"))
            if st in counts:
                counts[st] += 1
            else:
                counts["other"] += 1
            if st in ("open", "open|filtered"):
                svc = port.find("service")
                opens.append((pnum, st, svc.get("name") if svc is not None else ""))
    except Exception as ex:
        p("xml parse err %r" % ex)
    opens.sort()
    p("RESULT %s counts=%s opens=%s" % (ip, json.dumps(counts), json.dumps([o[0] for o in opens])))
    return opens, counts

def banner(ip, opens):
    ports = [o[0] for o in opens]
    if not ports:
        return
    plist = ",".join(str(x) for x in ports)
    xml = os.path.join(OUT, "ver_%s.xml" % ip.replace(".", "_"))
    cmd = ("sudo nmap -Pn -sS -sV --version-light --version-intensity 2 "
           "-p %s -oX %s %s" % (plist, xml, ip))
    p("### VER %s : %s" % (ip, cmd))
    rc, o, e, dt = sh(cmd, 300)
    p("ver rc=%s dt=%.1fs" % (rc, dt))
    try:
        tree = ET.parse(xml)
        for port in tree.getroot().iter("port"):
            if port.find("state").get("state") != "open":
                continue
            s = port.find("service")
            def g(k):
                return s.get(k, "") if s is not None else ""
            p("BANNER %s:%s name=%s product=%s version=%s extra=%s tunnel=%s" % (
                ip, port.get("portid"), g("name"), g("product"), g("version"), g("extrainfo"), g("tunnel")))
    except Exception as ex:
        p("ver xml parse err %r" % ex)
    # raw ASCII banner read for non-HTTP (best effort, 1 connect each)
    for pnum in ports:
        if pnum in (80, 443, 8080, 8443, 5678):
            continue
        try:
            sctx = socket.create_connection((ip, pnum), timeout=4)
            sctx.settimeout(3)
            try:
                data = sctx.recv(256)
            except socket.timeout:
                data = b""
            sctx.close()
            p("RAWBANNER %s:%s %r" % (ip, pnum, data[:120]))
        except Exception as ex:
            p("RAWBANNER %s:%s ERR %r" % (ip, pnum, str(ex)[:80]))

def http_probe(ip, opens):
    ports = [o[0] for o in opens if o[0] in (80, 443, 8080, 8443, 5678, 3000, 8000, 9090, 9100, 50070, 9000, 8200, 6443)]
    for pnum in ports:
        scheme = "https" if pnum in (443, 8443) else "http"
        url = "%s://%s:%s/" % (scheme, ip, pnum)
        rc, o, e, dt = sh("curl -sk -m 8 -D - -o /dev/null %s" % url, 20)
        first = ""
        for ln in o.splitlines():
            if ln.strip():
                first = ln.strip()
                break
        p("HTTP %s rc=%s first=%r" % (url, rc, first[:100]))
        # body title probe (1 more GET, tiny)
        rc2, o2, e2, dt2 = sh("curl -sk -m 8 %s" % url, 20)
        m = re.search(r"<title>(.*?)</title>", o2, re.I | re.S)
        p("HTTP %s bodylen=%d title=%r head=%r" % (url, len(o2), (m.group(1).strip()[:60] if m else ""), o2[:80].replace("\n", " ")))

def main():
    ip = egress()
    p("EGRESS_IP=%s" % ip)
    ensure_nmap()
    summary = []
    for ip in IPS:
        opens, counts = scan(ip)
        banner(ip, opens)
        http_probe(ip, opens)
        summary.append((ip, opens, counts))
    with open(os.path.join(OUT, "summary.txt"), "w") as f:
        f.write("egress_ip=%s\nnmap=%s\n\n" % (egress(), sh("nmap --version | head -1", 20)[1].strip()))
        for ipp, opens, counts in summary:
            f.write("## %s open_ports=%s counts=%s\n" % (ipp, json.dumps([o[0] for o in opens]), json.dumps(counts)))
            for o in opens:
                f.write("   port=%s state=%s svc=%s\n" % (o[0], o[1], o[2]))
    p("### DONE ###")

main()
