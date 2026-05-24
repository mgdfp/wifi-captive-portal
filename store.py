import json
import os
import threading
from datetime import datetime
from pathlib import Path

GUESTS_FILE = Path(__file__).parent / "data" / "guests.json"
_lock = threading.Lock()


def load_guests() -> dict:
    if not GUESTS_FILE.exists():
        return {}
    try:
        with open(GUESTS_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(guests: dict) -> None:
    """Write guests to disk atomically. Must be called while holding _lock."""
    tmp = GUESTS_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(guests, f, indent=2)
    os.replace(tmp, GUESTS_FILE)


def update_guests(fn) -> None:
    """Load guests, apply fn(guests), save atomically."""
    with _lock:
        guests = load_guests()
        fn(guests)
        _save(guests)


def find_by_mac(mac: str) -> tuple[str, dict] | None:
    """Return (phone, user) for the user who owns this MAC, or None."""
    mac = mac.lower()
    for phone, user in load_guests().items():
        if mac in user.get("macs", []):
            return phone, user
    return None


def find_by_phone(phone: str) -> dict | None:
    return load_guests().get(phone)


def add_blocked_user(phone: str, name: str, mac: str) -> None:
    def _apply(guests):
        guests[phone] = {
            "name": name,
            "status": "blocked",
            "macs": [mac.lower()],
            "limit_seconds": None,
            "seconds_today": 0,
            "throttled": False,
            "last_reset_date": datetime.now().date().isoformat(),
            "registered_at": datetime.now().isoformat(),
            "tx_bytes": {},
        }
    update_guests(_apply)


def approve_user(phone: str, limit_seconds: int | None) -> None:
    def _apply(guests):
        if phone in guests:
            guests[phone]["status"] = "approved"
            guests[phone]["limit_seconds"] = limit_seconds
    update_guests(_apply)


def add_user(phone: str, name: str, mac: str, limit_seconds: int | None) -> None:
    def _apply(guests):
        guests[phone] = {
            "name": name,
            "macs": [mac.lower()],
            "limit_seconds": limit_seconds,
            "seconds_today": 0,
            "throttled": False,
            "last_reset_date": datetime.now().date().isoformat(),
            "registered_at": datetime.now().isoformat(),
            "tx_bytes": {},
        }
    update_guests(_apply)


def add_mac_to_user(phone: str, mac: str) -> None:
    def _apply(guests):
        mac_lower = mac.lower()
        if phone in guests and mac_lower not in guests[phone]["macs"]:
            guests[phone]["macs"].append(mac_lower)
    update_guests(_apply)


def set_throttled(phone: str, throttled: bool) -> None:
    def _apply(guests):
        if phone in guests:
            guests[phone]["throttled"] = throttled
    update_guests(_apply)


def update_usage(phone: str, added_seconds: int, tx_bytes_map: dict) -> None:
    def _apply(guests):
        if phone in guests:
            guests[phone]["seconds_today"] = guests[phone].get("seconds_today", 0) + added_seconds
            guests[phone]["tx_bytes"] = tx_bytes_map
    update_guests(_apply)


def reset_all_daily(today: str) -> None:
    def _apply(guests):
        for user in guests.values():
            user["seconds_today"] = 0
            user["throttled"] = False
            user["last_reset_date"] = today
            user["tx_bytes"] = {}
    update_guests(_apply)


def set_limit(phone: str, limit_seconds: int | None) -> None:
    def _apply(guests):
        if phone in guests:
            guests[phone]["limit_seconds"] = limit_seconds
    update_guests(_apply)


def delete_user(phone: str) -> None:
    def _apply(guests):
        guests.pop(phone, None)
    update_guests(_apply)
