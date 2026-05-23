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
THROTTLE_PROFILE_ID = os.environ["THROTTLE_PROFILE_ID"]
TWILIO_SID          = os.environ["TWILIO_ACCOUNT_SID"]
TWILIO_TOKEN        = os.environ["TWILIO_AUTH_TOKEN"]
TWILIO_FROM         = os.environ["TWILIO_FROM_NUMBER"]
TELEGRAM_TOKEN      = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID    = os.environ["TELEGRAM_CHAT_ID"]
SECRET_KEY          = os.environ["SECRET_KEY"]
PORT                = int(os.getenv("PORT", "80"))
POLL_INTERVAL       = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))
ACTIVE_THRESHOLD    = int(os.getenv("ACTIVE_RATE_THRESHOLD_BYTES_PER_SEC", "6250"))
OTP_TTL_SECONDS     = 600  # 10 minutes

# ---------------------------------------------------------------------------
# Module init
# ---------------------------------------------------------------------------

unifi.init(UDM_IP, UNIFI_API_KEY, THROTTLE_PROFILE_ID)
sms.init(TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM)
telegram_bot.init(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)
monitor.init(POLL_INTERVAL, ACTIVE_THRESHOLD)

store.GUESTS_FILE.parent.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = SECRET_KEY

# In-memory OTP sessions: sid -> {phone, name, mac, target_url, otp, expires_at}
_otp_sessions: dict[str, dict] = {}
_otp_lock = threading.Lock()


def _new_otp() -> str:
    return f"{random.randint(0, 999999):06d}"


def _clean_expired() -> None:
    now = time.time()
    with _otp_lock:
        expired = [k for k, v in _otp_sessions.items() if v["expires_at"] < now]
        for k in expired:
            del _otp_sessions[k]


def _normalise_phone(raw: str) -> str:
    """Normalise to E.164. Bare digits get +47 prepended (Norwegian default)."""
    p = raw.strip().replace(" ", "").replace("-", "")
    if p.startswith("00"):
        p = "+" + p[2:]
    if not p.startswith("+"):
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
    return render_template("portal.html", error=None)


@app.route("/submit", methods=["POST"])
def submit():
    """Receive name + phone, send OTP."""
    name = request.form.get("name", "").strip()
    raw_phone = request.form.get("phone", "").strip()

    if not name or not raw_phone:
        return render_template("portal.html", error="Fyll inn både navn og telefonnummer.")

    phone = _normalise_phone(raw_phone)
    if not phone[1:].isdigit() or len(phone) < 8:
        return render_template("portal.html", error="Ugyldig telefonnummer. Prøv igjen.")

    mac = session.get("mac", "")
    target_url = session.get("target_url", "http://google.com")

    otp = _new_otp()
    sid = secrets.token_urlsafe(24)

    _clean_expired()
    with _otp_lock:
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

    session["sid"] = sid
    return render_template("verify.html", phone=phone, error=None)


@app.route("/verify", methods=["POST"])
def verify():
    """Check OTP. Approve returning users immediately; queue new users for Telegram approval."""
    sid = session.get("sid")
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
        return render_template("verify.html", phone=sess["phone"], error="Feil kode. Prøv igjen.")

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
    session["pending_sid"] = sid
    session["target_url"] = target_url
    return redirect(url_for("waiting"))


@app.route("/waiting")
def waiting():
    sid = session.get("pending_sid")
    if not sid:
        return redirect(url_for("index"))
    return render_template("waiting.html")


@app.route("/api/status")
def api_status():
    """Polled by the waiting page every 5 seconds."""
    sid = session.get("pending_sid")
    if not sid:
        return jsonify({"status": "error"})

    result = telegram_bot.get_pending_status(sid)
    if not result:
        return jsonify({"status": "error"})

    status = result["status"]

    if status == "approved":
        target_url = session.get("target_url", "http://google.com")
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
