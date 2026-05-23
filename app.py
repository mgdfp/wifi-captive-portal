#!/usr/bin/env python3
import logging
import os
import random
import secrets
import threading
import time
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

import monitor
import sms
import store
import telegram_bot
import unifi

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

UDM_IP              = os.environ["UDM_IP"]
UNIFI_API_KEY       = os.environ["UNIFI_API_KEY"]
THROTTLE_DOWN_KBPS  = int(os.getenv("THROTTLE_DOWN_KBPS", "500"))
THROTTLE_UP_KBPS    = int(os.getenv("THROTTLE_UP_KBPS", "250"))
TWILIO_SID          = os.environ["TWILIO_ACCOUNT_SID"]
TWILIO_TOKEN        = os.environ["TWILIO_AUTH_TOKEN"]
TWILIO_FROM         = os.environ["TWILIO_FROM_NUMBER"]
TELEGRAM_TOKEN      = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID    = os.environ["TELEGRAM_CHAT_ID"]
SECRET_KEY          = os.environ["SECRET_KEY"]
PORT                = int(os.getenv("PORT", "80"))
POLL_INTERVAL       = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))
ACTIVE_THRESHOLD    = int(os.getenv("ACTIVE_RATE_THRESHOLD_BYTES_PER_SEC", "6250"))
FAILSAFE_KBPS       = int(os.getenv("FAILSAFE_KBPS", "2000"))
OTP_TTL_SECONDS     = 600  # 10 minutes

# ---------------------------------------------------------------------------
# Module init
# ---------------------------------------------------------------------------

unifi.init(UDM_IP, UNIFI_API_KEY, THROTTLE_DOWN_KBPS, THROTTLE_UP_KBPS)
sms.init(TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM)
telegram_bot.init(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)
monitor.init(POLL_INTERVAL, ACTIVE_THRESHOLD, FAILSAFE_KBPS)

store.GUESTS_FILE.parent.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = SECRET_KEY

# In-memory OTP sessions: sid -> {phone, name, mac, target_url, otp, expires_at}
_otp_sessions: dict[str, dict] = {}
_sms_cooldown: dict[str, float] = {}      # phone -> last sent timestamp
_mac_attempts: dict[str, list] = {}       # mac -> [timestamps of OTP sends]
_otp_lock = threading.Lock()

SMS_COOLDOWN = 60        # seconds between OTPs to the same number
MAC_ATTEMPT_LIMIT = 5    # max OTPs per MAC per hour


def _new_otp() -> str:
    return f"{secrets.randbelow(1000000):06d}"


def _clean_expired() -> None:
    now = time.time()
    with _otp_lock:
        expired = [k for k, v in _otp_sessions.items() if v["expires_at"] < now]
        for k in expired:
            del _otp_sessions[k]
        stale = [p for p, t in _sms_cooldown.items() if now - t > SMS_COOLDOWN]
        for p in stale:
            del _sms_cooldown[p]
        for mac in list(_mac_attempts):
            _mac_attempts[mac] = [t for t in _mac_attempts[mac] if now - t < 3600]
            if not _mac_attempts[mac]:
                del _mac_attempts[mac]


def _normalise_phone(raw: str) -> str:
    """Normalise to E.164. Bare 8 digits get +47 prepended (Norwegian default)."""
    p = raw.strip().replace(" ", "").replace("-", "").replace(".", "")
    if p.startswith("0047"):
        p = "+47" + p[4:]
    elif p.startswith("00"):
        p = "+" + p[2:]
    elif p.startswith("47") and len(p) == 10:
        p = "+" + p
    elif not p.startswith("+"):
        p = "+47" + p
    return p


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/guest/s/<site>")
@app.route("/guest/s/<site>/")
@app.route("/")
def index(site=None):
    """Entry point — UniFi redirects guests here with ?id=<mac>&t=<url>"""
    mac = (request.args.get("id") or "").lower().strip()
    target_url = request.args.get("url") or "http://google.com"

    if not mac:
        return render_template("portal.html", error=None)

    result = store.find_by_mac(mac)
    if result:
        phone, user = result
        if user.get("throttled"):
            return render_template("exhausted.html", name=user["name"])
        unifi.authorize_guest(mac)
        log.info("Known device %s (%s) re-authorized.", mac, user["name"])
        return redirect(url_for("success", next=target_url))

    session["mac"] = mac
    session["target_url"] = target_url
    return render_template("portal.html", mac=mac, target_url=target_url, error=None)


@app.route("/submit", methods=["POST"])
def submit():
    """Receive name + phone, send OTP."""
    name = request.form.get("name", "").strip()
    raw_phone = request.form.get("phone", "").strip()

    mac = request.form.get("mac") or session.get("mac", "")
    target_url = request.form.get("target_url") or session.get("target_url", "http://google.com")

    if not name or not raw_phone:
        return render_template("portal.html", mac=mac, target_url=target_url, error="Fyll inn både navn og telefonnummer.")

    phone = _normalise_phone(raw_phone)
    if not (phone.startswith("+47") and len(phone) == 11 and phone[1:].isdigit()):
        return render_template("portal.html", mac=mac, target_url=target_url, error="Ugyldig telefonnummer. Skriv inn 8 siffer.")

    _clean_expired()
    with _otp_lock:
        last_sent = _sms_cooldown.get(phone, 0)
        wait = int(SMS_COOLDOWN - (time.time() - last_sent))
        if wait > 0:
            return render_template("verify.html", phone=phone, error=f"Vent {wait} sekunder før du ber om ny kode.")
        attempts = _mac_attempts.get(mac, [])
        if len(attempts) >= MAC_ATTEMPT_LIMIT:
            log.warning("MAC %s hit OTP attempt limit — blocking further sends.", mac)
            return render_template("portal.html", mac=mac, target_url=target_url, error="For mange forsøk. Kontakt administrator for å få tilgang.")

    otp = _new_otp()
    sid = secrets.token_urlsafe(24)

    with _otp_lock:
        _sms_cooldown[phone] = time.time()
        _mac_attempts.setdefault(mac, []).append(time.time())
        _otp_sessions[sid] = {
            "phone": phone,
            "name": name,
            "mac": mac,
            "target_url": target_url,
            "otp": otp,
            "expires_at": time.time() + OTP_TTL_SECONDS,
        }

    if not sms.send_otp(phone, otp):
        return render_template("portal.html", error="Kunne ikke sende SMS. Sjekk nummeret og prøv igjen.")

    return render_template("verify.html", sid=sid, phone=phone, error=None)


@app.route("/verify", methods=["POST"])
def verify():
    """Check OTP. Approve returning users immediately; queue new users for Telegram approval."""
    sid = request.form.get("sid", "")
    code = request.form.get("code", "").strip()

    with _otp_lock:
        sess = _otp_sessions.get(sid)

    if not sess:
        return render_template("verify.html", phone="", error="Sesjonen er utløpt. Start på nytt.")

    if time.time() > sess["expires_at"]:
        with _otp_lock:
            _otp_sessions.pop(sid, None)
        return render_template("portal.html", error="Koden er utløpt. Prøv igjen.")

    if code != sess["otp"]:
        with _otp_lock:
            sess["attempts"] = sess.get("attempts", 0) + 1
            if sess["attempts"] >= 5:
                _otp_sessions.pop(sid, None)
                return render_template("portal.html", mac="", target_url="", error="For mange feil koder. Be om en ny kode.")
        return render_template("verify.html", sid=sid, phone=sess["phone"], error=f"Feil kode. Prøv igjen. ({sess['attempts']}/5)")

    phone = sess["phone"]
    name = sess["name"]
    mac = sess["mac"]
    target_url = sess["target_url"]

    with _otp_lock:
        _otp_sessions.pop(sid, None)

    existing = store.find_by_phone(phone)
    if existing:
        store.add_mac_to_user(phone, mac)
        unifi.authorize_guest(mac)
        log.info("Returning user %s (%s) connected from %s.", existing["name"], phone, mac)
        session.clear()
        return redirect(url_for("success", next=target_url))

    telegram_bot.register_pending(sid, name, phone, mac)
    telegram_bot.notify_new_guest(sid, name, phone)
    return redirect(url_for("waiting", sid=sid, next=target_url))


@app.route("/waiting")
def waiting():
    sid = request.args.get("sid") or session.get("pending_sid")
    if not sid:
        return redirect(url_for("index"))
    target_url = request.args.get("next", "http://google.com")
    return render_template("waiting.html", sid=sid, target_url=target_url)


@app.route("/api/status")
def api_status():
    """Polled by the waiting page every 5 seconds."""
    sid = request.args.get("sid") or session.get("pending_sid")
    if not sid:
        return jsonify({"status": "error"})

    result = telegram_bot.get_pending_status(sid)
    if not result:
        return jsonify({"status": "error"})

    status = result["status"]

    if status == "approved":
        target_url = request.args.get("next", session.get("target_url", "http://google.com"))
        telegram_bot.clear_pending(sid)
        session.clear()
        return jsonify({"status": "approved", "redirect": url_for("success", next=target_url)})

    if status == "denied":
        telegram_bot.clear_pending(sid)
        session.clear()
        return jsonify({"status": "denied"})

    return jsonify({"status": "pending"})


@app.route("/success")
def success():
    next_url = request.args.get("next", "http://google.com")
    return render_template("success.html", next_url=next_url)


@app.route("/denied")
def denied():
    return render_template("denied.html")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    monitor.start()
    telegram_bot.start()
    log.info("Starting captive portal on port %d.", PORT)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
