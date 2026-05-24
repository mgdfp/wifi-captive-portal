import logging
import os
import threading
import time

import requests

import sms
import store
import unifi

_wifi_name = os.getenv("WIFI_NETWORK_NAME", "WiFi-nettverket")

log = logging.getLogger(__name__)

_token = None
_chat_id = None
_offset = 0
_lock = threading.Lock()

# pending[sid] = {"name": ..., "phone": ..., "mac": ..., "status": "pending"|"approved"|"denied", "limit_seconds": ...}
_pending: dict[str, dict] = {}
_pending_lock = threading.Lock()


def init(bot_token: str, chat_id: str) -> None:
    global _token, _chat_id
    _token = bot_token
    _chat_id = chat_id


def _post(method: str, **kwargs) -> dict | None:
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{_token}/{method}",
            timeout=10,
            **kwargs,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        log.error("Telegram %s failed: %s", method, e)
        return None


def send(text: str) -> None:
    _post("sendMessage", json={"chat_id": _chat_id, "text": text})


def _send_buttons(text: str, keyboard: list) -> None:
    _post("sendMessage", json={
        "chat_id": _chat_id,
        "text": text,
        "reply_markup": {"inline_keyboard": keyboard},
    })


def _answer_callback(callback_id: str, text: str = "") -> None:
    _post("answerCallbackQuery", json={"callback_query_id": callback_id, "text": text})


def _fmt_limit(limit_seconds: int | None) -> str:
    if not limit_seconds:
        return "ubegrenset"
    if limit_seconds < 3600:
        return f"{limit_seconds // 60}min"
    return f"{limit_seconds // 3600}t"


def _quota_keyboard(callback_prefix: str) -> list:
    """Inline keyboard for picking a quota. callback_prefix gets :<seconds> appended."""
    return [
        [
            {"text": "5min",  "callback_data": f"{callback_prefix}:300"},
            {"text": "15min", "callback_data": f"{callback_prefix}:900"},
            {"text": "30min", "callback_data": f"{callback_prefix}:1800"},
        ],
        [
            {"text": "1t",    "callback_data": f"{callback_prefix}:3600"},
            {"text": "2t",    "callback_data": f"{callback_prefix}:7200"},
            {"text": "4t",    "callback_data": f"{callback_prefix}:14400"},
        ],
        [
            {"text": "Ubegrenset", "callback_data": f"{callback_prefix}:0"},
        ],
    ]


# ---------------------------------------------------------------------------
# Pending approval queue
# ---------------------------------------------------------------------------

def register_pending(sid: str, name: str, phone: str, mac: str) -> None:
    with _pending_lock:
        _pending[sid] = {"name": name, "phone": phone, "mac": mac,
                         "status": "pending", "limit_seconds": None}


def get_pending_status(sid: str) -> dict | None:
    with _pending_lock:
        return dict(_pending[sid]) if sid in _pending else None


def clear_pending(sid: str) -> None:
    with _pending_lock:
        _pending.pop(sid, None)


def notify_new_guest(sid: str, name: str, phone: str) -> None:
    keyboard = _quota_keyboard(f"approve:{sid}")
    keyboard.append([{"text": "🚫 Avvis", "callback_data": f"deny:{sid}"}])
    _send_buttons(f"🔔 Ny gjest: {name} ({phone})\nDaglig kvote:", keyboard)


# ---------------------------------------------------------------------------
# Callback query handler (button taps)
# ---------------------------------------------------------------------------

def _handle_callback(callback_id: str, data: str) -> None:
    parts = data.split(":")

    if parts[0] == "approve" and len(parts) == 3:
        sid, raw_limit = parts[1], parts[2]
        limit_seconds = int(raw_limit) or None

        with _pending_lock:
            req = _pending.get(sid)
            if not req:
                _answer_callback(callback_id, "Forespørselen er utløpt.")
                return
            req["status"] = "approved"
            req["limit_seconds"] = limit_seconds
            name, phone, mac = req["name"], req["phone"], req["mac"]

        store.approve_user(phone, limit_seconds)
        store.add_mac_to_user(phone, mac)
        unifi.authorize_guest(mac)
        limit_str = _fmt_limit(limit_seconds)
        _answer_callback(callback_id, f"Godkjent — {limit_str}")
        send(f"✅ {name} er godkjent ({limit_str}).")
        log.info("Approved %s (%s) with limit %s.", name, phone, limit_seconds)

    elif parts[0] == "deny" and len(parts) == 2:
        sid = parts[1]
        with _pending_lock:
            req = _pending.get(sid)
            if not req:
                _answer_callback(callback_id, "Forespørselen er utløpt.")
                return
            req["status"] = "denied"
            name = req["name"]

        _answer_callback(callback_id, "Avvist.")
        send(f"🚫 {name} ble avvist.")
        log.info("Denied guest %s.", name)

    elif parts[0] == "modify_pick" and len(parts) == 2:
        phone = parts[1]
        user = store.find_by_phone(phone)
        if not user:
            _answer_callback(callback_id, "Bruker ikke funnet.")
            return
        _answer_callback(callback_id)
        used_min = user.get("seconds_today", 0) // 60
        limit_str = _fmt_limit(user.get("limit_seconds"))
        devices = user.get("devices", {})
        device_lines = []
        for mac in user.get("macs", []):
            info = devices.get(mac, {})
            hostname = info.get("hostname", "")
            oui = info.get("oui", "")
            label = hostname or oui or "ukjent enhet"
            device_lines.append(f"  • {label} ({mac})")
        if user.get("status") == "blocked":
            keyboard = [
                [{"text": "✅ Godkjenn",   "callback_data": f"action:{phone}:approve"}],
                [{"text": "🗑️ Slett",     "callback_data": f"action:{phone}:delete"}],
            ]
            status_str = "⏳ blokkert (venter)"
        else:
            keyboard = [
                [{"text": "✏️ Endre kvote",    "callback_data": f"action:{phone}:quota"}],
                [{"text": "🚫 Blokker",        "callback_data": f"action:{phone}:block"}],
                [{"text": "🔄 Nullstill",      "callback_data": f"action:{phone}:reset"}],
                [{"text": "🗑️ Slett",          "callback_data": f"action:{phone}:delete"}],
            ]
            status_str = "🚫 blokkert" if user.get("throttled") else f"{used_min}min brukt"
        device_section = "\n".join(device_lines) if device_lines else "  (ingen enheter registrert)"
        _send_buttons(
            f"{user['name']} ({phone})\nStatus: {status_str} — kvote: {limit_str}\nEnheter:\n{device_section}\nHva vil du gjøre?",
            keyboard,
        )

    elif parts[0] == "action" and len(parts) == 3:
        phone, action = parts[1], parts[2]
        user = store.find_by_phone(phone)
        if not user:
            _answer_callback(callback_id, "Bruker ikke funnet.")
            return
        macs = user.get("macs", [])

        if action == "approve":
            _answer_callback(callback_id)
            _send_buttons(f"Daglig kvote for {user['name']}:", _quota_keyboard(f"approve_blocked:{phone}"))

        elif action == "quota":
            _answer_callback(callback_id)
            _send_buttons(f"Ny daglig kvote for {user['name']}:", _quota_keyboard(f"set_quota:{phone}"))

        elif action == "block":
            for mac in macs:
                unifi.throttle_client(mac)
            store.set_throttled(phone, True)
            _answer_callback(callback_id, "Blokkert.")
            send(f"🚫 {user['name']} er blokkert. Bruk Nullstill for å åpne igjen.")

        elif action == "reset":
            for mac in macs:
                unifi.unthrottle_client(mac)
                # re-authorize in case admin had previously used "block" (which unauthorizes)
                unifi.authorize_guest(mac)
            store.update_guests(lambda g: g[phone].update({
                "seconds_today": 0, "throttled": False, "tx_bytes": {}
            }) if phone in g else None)
            _answer_callback(callback_id, "Nullstilt.")
            send(f"🔄 {user['name']} er nullstilt og frigjort.")

        elif action == "delete":
            for mac in macs:
                unifi.unauthorize_guest(mac)
            store.delete_user(phone)
            _answer_callback(callback_id, "Slettet.")
            send(f"🗑️ {user['name']} er slettet.")

    elif parts[0] == "approve_blocked" and len(parts) == 3:
        phone, raw_limit = parts[1], parts[2]
        limit_seconds = int(raw_limit) or None
        user = store.find_by_phone(phone)
        if not user:
            _answer_callback(callback_id, "Bruker ikke funnet.")
            return
        store.approve_user(phone, limit_seconds)
        for mac in user.get("macs", []):
            unifi.authorize_guest(mac)
        sms.send_sms(phone, f"Du har fått tilgang til internett — koble til {_wifi_name} på nytt.")
        limit_str = _fmt_limit(limit_seconds)
        _answer_callback(callback_id, f"Godkjent — {limit_str}")
        send(f"✅ {user['name']} er godkjent ({limit_str}) og varslet på SMS.")
        log.info("Approved blocked user %s (%s) with limit %s.", user["name"], phone, limit_seconds)

    elif parts[0] == "set_quota" and len(parts) == 3:
        phone, raw_limit = parts[1], parts[2]
        limit_seconds = int(raw_limit) or None
        user = store.find_by_phone(phone)
        if not user:
            _answer_callback(callback_id, "Bruker ikke funnet.")
            return
        store.set_limit(phone, limit_seconds)
        limit_str = _fmt_limit(limit_seconds)
        _answer_callback(callback_id, f"Kvote satt til {limit_str}")
        send(f"✅ {user['name']}s kvote er satt til {limit_str}.")
        log.info("Quota for %s set to %s via Telegram.", user["name"], limit_seconds)


# ---------------------------------------------------------------------------
# Text command handler
# ---------------------------------------------------------------------------

def _handle_command(text: str) -> None:
    text = text.strip()
    cmd = text.lower().split()[0] if text else ""

    if cmd == "/list":
        guests = store.load_guests()
        if not guests:
            send("Ingen brukere registrert ennå.")
            return
        approved = [(p, u) for p, u in guests.items() if u.get("status") != "blocked"]
        blocked = [(p, u) for p, u in guests.items() if u.get("status") == "blocked"]
        lines = []
        if approved:
            lines.append("✅ Godkjente:\n")
            for phone, user in approved:
                used_min = user.get("seconds_today", 0) // 60
                throttled = user.get("throttled", False)
                limit_str = _fmt_limit(user.get("limit_seconds"))
                n = len(user.get("macs", []))
                status = "🚫 throttlet" if throttled else f"{used_min}min brukt"
                lines.append(f"• {user['name']} — {status} / {limit_str} — {n} enhet{'er' if n > 1 else ''}")
        if blocked:
            if approved:
                lines.append("")
            lines.append("⏳ Venter på godkjenning:\n")
            for phone, user in blocked:
                lines.append(f"• {user['name']} ({phone})")
        send("\n".join(lines))

    elif cmd == "/modify":
        guests = store.load_guests()
        if not guests:
            send("Ingen brukere å endre.")
            return
        approved = [(p, u) for p, u in guests.items() if u.get("status") != "blocked"]
        blocked = [(p, u) for p, u in guests.items() if u.get("status") == "blocked"]
        keyboard = []
        if approved:
            keyboard.append([{"text": "— Godkjente —", "callback_data": "noop"}])
            for phone, user in approved:
                keyboard.append([{"text": user["name"], "callback_data": f"modify_pick:{phone}"}])
        if blocked:
            keyboard.append([{"text": "— Venter —", "callback_data": "noop"}])
            for phone, user in blocked:
                keyboard.append([{"text": f"⏳ {user['name']}", "callback_data": f"modify_pick:{phone}"}])
        _send_buttons("Velg bruker:", keyboard)

    else:
        send(
            "Tilgjengelige kommandoer:\n"
            "/list — vis alle brukere\n"
            "/modify — endre kvote / blokker / nullstill"
        )


# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------

def _poll() -> None:
    global _offset
    try:
        resp = requests.get(
            f"https://api.telegram.org/bot{_token}/getUpdates",
            params={"offset": _offset, "timeout": 30},
            timeout=40,
        )
        resp.raise_for_status()
        for update in resp.json().get("result", []):
            _offset = update["update_id"] + 1

            cb = update.get("callback_query")
            if cb:
                chat_id = str(cb.get("message", {}).get("chat", {}).get("id", ""))
                if chat_id == _chat_id:
                    _handle_callback(cb["id"], cb.get("data", ""))
                continue

            msg = update.get("message", {})
            chat_id = str(msg.get("chat", {}).get("id", ""))
            if chat_id != _chat_id:
                continue
            text = msg.get("text", "").strip()
            if text:
                _handle_command(text)

    except requests.RequestException as e:
        log.error("Telegram poll failed: %s", e)
        time.sleep(5)


def _run() -> None:
    log.info("Telegram bot polling started.")
    _register_commands()
    while True:
        try:
            _poll()
        except Exception:
            log.exception("Unhandled error in Telegram loop.")
            time.sleep(5)


def _register_commands() -> None:
    _post("setMyCommands", json={"commands": [
        {"command": "list",   "description": "Vis alle brukere og forbruk"},
        {"command": "modify", "description": "Endre kvote / blokker / nullstill"},
    ]})


def start() -> None:
    t = threading.Thread(target=_run, name="telegram", daemon=True)
    t.start()
