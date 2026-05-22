import logging
import threading
import time

import requests

import store
import unifi

log = logging.getLogger(__name__)

_token = None
_chat_id = None
_offset = 0
_lock = threading.Lock()

# pending[sid] = {"name": ..., "phone": ..., "mac": ..., "status": "pending"|"approved"|"denied", "limit_seconds": ...}
_pending: dict[str, dict] = {}
_pending_lock = threading.Lock()

# Conversation state for /modify
_conversation: dict = {"step": None}


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
    keyboard = [
        [
            {"text": "1h",  "callback_data": f"approve:{sid}:3600"},
            {"text": "2h",  "callback_data": f"approve:{sid}:7200"},
            {"text": "4h",  "callback_data": f"approve:{sid}:14400"},
        ],
        [
            {"text": "Unlimited", "callback_data": f"approve:{sid}:0"},
            {"text": "Deny",      "callback_data": f"deny:{sid}"},
        ],
    ]
    _send_buttons(
        f"\U0001f514 New guest: {name} ({phone})\nHow much internet today?",
        keyboard,
    )


# ---------------------------------------------------------------------------
# Callback query handler (button taps)
# ---------------------------------------------------------------------------

def _handle_callback(callback_id: str, data: str) -> None:
    parts = data.split(":")

    if parts[0] == "approve" and len(parts) == 3:
        sid, raw_limit = parts[1], parts[2]
        limit_seconds = int(raw_limit) or None  # 0 means unlimited

        with _pending_lock:
            req = _pending.get(sid)
            if not req:
                _answer_callback(callback_id, "Request expired.")
                return
            req["status"] = "approved"
            req["limit_seconds"] = limit_seconds
            name, phone, mac = req["name"], req["phone"], req["mac"]

        store.add_user(phone, name, mac, limit_seconds)
        unifi.authorize_guest(mac)
        limit_str = f"{limit_seconds // 3600}h" if limit_seconds else "unlimited"
        _answer_callback(callback_id, f"Approved — {limit_str}")
        send(f"✅ {name} approved ({limit_str}).")
        log.info("Approved %s (%s) with limit %s.", name, phone, limit_seconds)

    elif parts[0] == "deny" and len(parts) == 2:
        sid = parts[1]
        with _pending_lock:
            req = _pending.get(sid)
            if not req:
                _answer_callback(callback_id, "Request expired.")
                return
            req["status"] = "denied"
            name = req["name"]

        _answer_callback(callback_id, "Denied.")
        send(f"❌ {name} denied.")
        log.info("Denied guest %s.", name)

    elif parts[0] == "modify_pick" and len(parts) == 2:
        phone = parts[1]
        user = store.find_by_phone(phone)
        if not user:
            _answer_callback(callback_id, "User not found.")
            return
        _answer_callback(callback_id)
        limit_str = f"{user['limit_seconds'] // 3600}h" if user.get("limit_seconds") else "unlimited"
        used_min = user.get("seconds_today", 0) // 60
        keyboard = [
            [{"text": "✏️ Change quota",    "callback_data": f"action:{phone}:quota"}],
            [{"text": "\U0001f6ab Block now",         "callback_data": f"action:{phone}:block"}],
            [{"text": "\U0001f504 Reset today",       "callback_data": f"action:{phone}:reset"}],
            [{"text": "\U0001f5d1️ Delete user", "callback_data": f"action:{phone}:delete"}],
        ]
        _send_buttons(
            f"{user['name']} ({phone})\nUsed today: {used_min}min — quota: {limit_str}\nWhat to do?",
            keyboard,
        )

    elif parts[0] == "action" and len(parts) == 3:
        phone, action = parts[1], parts[2]
        user = store.find_by_phone(phone)
        if not user:
            _answer_callback(callback_id, "User not found.")
            return
        macs = user.get("macs", [])

        if action == "quota":
            _answer_callback(callback_id)
            with _lock:
                _conversation["step"] = "awaiting_quota"
                _conversation["phone"] = phone
            send(f"New daily quota for {user['name']}?\nType e.g. 1h, 2h, 4h, or 'unlimited':")

        elif action == "block":
            for mac in macs:
                unifi.throttle_client(mac)
                unifi.unauthorize_guest(mac)
            store.set_throttled(phone, True)
            _answer_callback(callback_id, "Blocked.")
            send(f"\U0001f6ab {user['name']} blocked. Use Reset to restore.")

        elif action == "reset":
            for mac in macs:
                unifi.unthrottle_client(mac)
                unifi.authorize_guest(mac)
            store.update_guests(lambda g: g[phone].update({
                "seconds_today": 0, "throttled": False, "notified_half": False, "tx_bytes": {}
            }) if phone in g else None)
            _answer_callback(callback_id, "Reset.")
            send(f"\U0001f504 {user['name']} reset and unblocked.")

        elif action == "delete":
            for mac in macs:
                unifi.unauthorize_guest(mac)
            store.delete_user(phone)
            _answer_callback(callback_id, "Deleted.")
            send(f"\U0001f5d1️ {user['name']} deleted.")


# ---------------------------------------------------------------------------
# Text command handler
# ---------------------------------------------------------------------------

def _parse_hours(text: str) -> int | None:
    """Parse '1h', '2h', 'unlimited' -> seconds or None. Raises ValueError."""
    t = text.strip().lower()
    if t == "unlimited":
        return None
    if t.endswith("h"):
        return int(t[:-1]) * 3600
    raise ValueError(f"Cannot parse {text!r}")


def _handle_command(text: str) -> None:
    global _conversation
    text = text.strip()
    cmd = text.lower().split()[0] if text else ""

    with _lock:
        step = _conversation.get("step")

    if cmd == "/cancel":
        with _lock:
            _conversation = {"step": None}
        send("❌ Cancelled.")
        return

    # Active conversation takes priority over new commands
    if step == "awaiting_quota":
        with _lock:
            phone = _conversation.get("phone")
        try:
            limit_seconds = _parse_hours(text)
        except ValueError:
            send("❌ Type e.g. 1h, 2h, 4h, or 'unlimited':")
            return
        store.set_limit(phone, limit_seconds)
        user = store.find_by_phone(phone)
        name = user["name"] if user else phone
        limit_str = f"{limit_seconds // 3600}h" if limit_seconds else "unlimited"
        send(f"✅ {name}'s quota set to {limit_str}.")
        with _lock:
            _conversation = {"step": None}
        return

    if cmd == "/list":
        guests = store.load_guests()
        if not guests:
            send("No users registered yet.")
            return
        lines = ["\U0001f4cb Current users:\n"]
        for phone, user in guests.items():
            limit_seconds = user.get("limit_seconds")
            limit_str = f"{limit_seconds // 3600}h" if limit_seconds else "unlimited"
            used_min = user.get("seconds_today", 0) // 60
            throttled = user.get("throttled", False)
            n_devices = len(user.get("macs", []))
            status = "\U0001f6ab throttled" if throttled else f"{used_min}min used"
            lines.append(f"• {user['name']} — {status} / {limit_str} — {n_devices} device(s)")
        send("\n".join(lines))

    elif cmd == "/modify":
        guests = store.load_guests()
        if not guests:
            send("No users to modify.")
            return
        keyboard = [
            [{"text": user["name"], "callback_data": f"modify_pick:{phone}"}]
            for phone, user in guests.items()
        ]
        _send_buttons("Which user?", keyboard)

    else:
        send(
            "Commands:\n"
            "/list — show all users\n"
            "/modify — change quota / block / reset\n"
            "/cancel — cancel active action"
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
        {"command": "list",   "description": "Show all users and usage"},
        {"command": "modify", "description": "Change quota / block / reset a user"},
        {"command": "cancel", "description": "Cancel active action"},
    ]})


def start() -> None:
    t = threading.Thread(target=_run, name="telegram", daemon=True)
    t.start()
