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
PORT                = int(os.getenv("PORT", "8080"))
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/guest/s/<site>")
@app.route("/guest/s/<site>/")
@app.route("/")
def index(site=None):
    """Entry point — UniFi redirects guests here with ?id=<mac>&t=<url>"""
    mac = (request.args.get("id") or "").lower().strip()
    target_url = request.args.get("t") or request.args.get("url") or "http://google.com"

    if not mac:
        # Direct browser hit without UniFi redirect — show generic portal
        return render_template("portal.html", error=None)

    result = store.find_by_mac(mac)
    if result:
        phone, user = result
        if user.get("throttled"):
            return render_template("exhausted.html", name=user["name"])
        # Known device, quota OK — silently re-authorize and send them through
        unifi.authorize_guest(mac)
        log.info("Known device %s (%s) re-authorized.", mac, user["name"])
        return redirect(target_url)

    # Unknown MAC — start registration
    session["mac"] = mac
    session["target_url"] = target_url
    return render_template("portal.html", error=None)


@app.route("/submit", methods=["POST"])
def submit():
    """Receive name + phone, send OTP."""
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()

    if not name or not phone:
        return render_template("portal.html", error="Please fill in both fields.")

    # Normalise phone: must start with + and contain only digits after
    phone = phone.replace(" ", "").replace("-", "")
    if not phone.startswith("+") or not phone[1:].isdigit() or len(phone) < 8:
        return render_template("portal.html", error="Enter phone in international format, e.g. +4712345678")

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
        return render_template("portal.html", error="Could not send SMS. Check your number and try again.")

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
        return render_template("verify.html", phone="", error="Session expired. Please start again.")

    if time.time() > sess["expires_at"]:
        with _otp_lock:
            _otp_sessions.pop(sid, None)
        return render_template("portal.html", error="Code expired. Please try again.")

    if code != sess["otp"]:
        return render_template("verify.html", phone=sess["phone"], error="Wrong code. Try again.")

    # OTP correct — phone ownership confirmed
    phone = sess["phone"]
    name = sess["name"]
    mac = sess["mac"]
    target_url = sess["target_url"]

    with _otp_lock:
        _otp_sessions.pop(sid, None)

    existing = store.find_by_phone(phone)
    if existing:
        # Returning user — add MAC if new, authorize immediately
        store.add_mac_to_user(phone, mac)
        unifi.authorize_guest(mac)
        log.info("Returning user %s (%s) connected from %s.", name, phone, mac)
        session.clear()
        return redirect(target_url)

    # New user — request admin approval via Telegram
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
        return jsonify({"status": "approved", "redirect": target_url})

    if status == "denied":
        telegram_bot.clear_pending(sid)
        session.clear()
        return jsonify({"status": "denied"})

    return jsonify({"status": "pending"})


@app.route("/success")
def success():
    return render_template("success.html")


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
