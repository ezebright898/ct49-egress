#!/usr/bin/env python3
"""ct49 identifier probe: for each email in idprobe.json, only type the identifier
and classify the resulting page state. No password is ever submitted. Read-only wrt Google."""
import sys, json, os, re, time, random
from playwright.sync_api import sync_playwright

EMAILS = json.load(open('idprobe.json'))['emails']
OUT = 'out/idprobe'
os.makedirs(OUT, exist_ok=True)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
START = ("https://accounts.google.com/v3/signin/identifier?hl=en&flowName=GlifWebSignIn"
         "&flowEntry=ServiceLogin&continue=https%3A%2F%2Fmyaccount.google.com%2F&service=accountsettings")

def txt(pg):
    try:
        return pg.evaluate("document.body?document.body.innerText:''") or ""
    except Exception:
        return ""

def captcha(t):
    t = t.lower()
    return ("type the text you hear or see" in t) or ("unusual traffic" in t) or \
           ("please re-enter the characters" in t) or ("type the text you hear" in t)

def classify(t, url):
    tl = t.replace("\u2019", "'").lower()
    if "couldn't find your google account" in tl or "couldn't find this account" in tl \
       or "that account doesn't exist" in tl or "account doesn't exist" in tl:
        return "ACCOUNT_NOT_FOUND"
    if "may not be secure" in tl or "browser or app" in tl:
        return "NOT_SECURE"
    if "wrong password" in tl:
        return "WRONG_PASSWORD"
    if captcha(tl):
        return "CAPTCHA"
    for k in ["2-step verification", "verify it's you", "verify it is you", "enter a code",
              "tap yes", "check your phone", "couldn't verify", "verify your identity",
              "choose how you want to sign in", "get a verification code", "is this your account",
              "first verify", "confirm your recovery", "passkey", "use your passkey",
              "enter the code", "check your email"]:
        if k in tl:
            return "2SV_OR_CHALLENGE"
    if url.startswith("https://myaccount.google.com") or "mail.google.com/mail/u/0" in url:
        return "SUCCESS"
    if "enter your password" in tl:
        return "PASSWORD_PAGE"
    return "UNKNOWN"

def human_fill(el, s):
    el.click(); time.sleep(0.15)
    for ch in s:
        el.type(ch, delay=random.randint(40, 100))
    time.sleep(0.2)

res = []
with sync_playwright() as p:
    b = p.chromium.launch(headless=False, args=[
        "--disable-blink-features=AutomationControlled", "--no-sandbox",
        "--disable-dev-shm-usage", "--disable-gpu"])
    for em in EMAILS:
        ctx = b.new_context(user_agent=UA, locale="en-US", timezone_id="Africa/Lagos",
                            viewport={"width": 1366, "height": 800})
        ctx.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
            "Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});"
            "if(!window.chrome){window.chrome={runtime:{}};}")
        pg = ctx.new_page()
        rec = {"email": em}
        try:
            pg.goto(START, timeout=60000, wait_until="domcontentloaded")
            pg.wait_for_timeout(2600)
            inp = pg.locator('input[name="identifier"]')
            if inp.count():
                el = inp.first
                human_fill(el, em)
                clicked = False
                for bt in pg.locator('button').all():
                    try:
                        if (bt.inner_text() or '').strip().lower() == 'next' and bt.is_visible():
                            bt.click(); clicked = True; break
                    except Exception:
                        pass
                if not clicked:
                    el.press("Enter")
            pg.wait_for_timeout(5200)
            t = txt(pg)
            rec.update({"state": classify(t, pg.url), "url": pg.url,
                        "text": re.sub(r'\n{3,}', '\n\n', t)[:1800]})
            try:
                open(f"{OUT}/id_{em.split('@')[0]}.txt", "w").write(t[:200000])
                pg.screenshot(path=f"{OUT}/id_{em.split('@')[0]}.png")
            except Exception:
                pass
        except Exception as e:
            rec.update({"state": "ERROR", "err": str(e)[:300]})
        print(json.dumps(rec, ensure_ascii=False)[:700], flush=True)
        res.append(rec)
        try:
            ctx.close()
        except Exception:
            pass
        time.sleep(1.5)
    b.close()
json.dump(res, open(OUT + "/report.json", "w"), ensure_ascii=False, indent=1)
print("=== idprobe report ===", flush=True)
for r in res:
    print(r.get("email"), "->", r.get("state"), flush=True)
