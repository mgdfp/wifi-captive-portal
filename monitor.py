import logging
import threading
import time
from datetime import date

import store
import gateway

log = logging.getLogger(__name__)

_poll_interval = 300
_active_threshold = 6250       # bytes/sec
_failsafe_threshold = 250000   # bytes/sec (2 Mbps) — kick if throttle clearly not holding


def init(poll_interval: int, active_threshold: int, failsafe_kbps: int = 2000) -> None:
    global _poll_interval, _active_threshold, _failsafe_threshold
    _poll_interval = poll_interval
    _active_threshold = active_threshold
    _failsafe_threshold = failsafe_kbps * 1000 / 8


def _run_reset(today: str) -> None:
    log.info("Daily reset: unthrottling all users.")
    guests = store.load_guests()
    for phone, user in guests.items():
        if user.get("status") == "blocked":
            continue
        if user.get("throttled"):
            for mac in user.get("macs", []):
                gateway.unthrottle_client(mac)
                gateway.authorize_guest(mac)  # re-authorize in case failsafe had kicked them off
    store.reset_all_daily(today)
    log.info("Daily reset complete.")


def _check_throttle_failsafe(phone: str, user: dict, active: dict) -> None:
    import telegram_bot
    macs = user.get("macs", [])
    tx_bytes_map = dict(user.get("tx_bytes", {}))
    changed = False

    for mac in macs:
        client = active.get(mac)
        if client is None:
            if mac in tx_bytes_map:
                tx_bytes_map.pop(mac)
                changed = True
            continue

        tx = client.get("tx_bytes") or 0
        prev = tx_bytes_map.get(mac)
        tx_bytes_map[mac] = tx
        changed = True

        if prev is None:
            continue  # first observation after throttle — establishing baseline

        delta = tx - prev
        if delta < 0:
            continue

        rate = delta / _poll_interval
        rate_kbps = rate * 8 / 1000
        if rate > _failsafe_threshold:
            log.warning(
                "%s (%s) still at %.0f kbps after throttle — kicking off WiFi.",
                user["name"], mac, rate_kbps,
            )
            gateway.unthrottle_client(mac)   # remove stale tc rules before kick
            gateway.unauthorize_guest(mac)
            telegram_bot.send(
                f"⚠️ Failsafe: {user['name']} kastet av WiFi "
                f"({rate_kbps:.0f} kbps — throttling virket ikke)."
            )
        else:
            log.info("%s (%s) throttle holding at %.0f kbps.", user["name"], mac, rate_kbps)

    if changed:
        store.update_guests(lambda g: g[phone].update({"tx_bytes": tx_bytes_map}) if phone in g else None)


def _run_monitor() -> None:
    active = gateway.fetch_active_clients()
    if active is None:
        log.warning("API error — skipping poll.")
        return

    guests = store.load_guests()
    log.info("--- Poll: %d device(s) on network ---", len(active))

    for phone, user in guests.items():
        if user.get("status") == "blocked":
            continue
        if user.get("throttled"):
            _check_throttle_failsafe(phone, user, active)
            continue

        macs = user.get("macs", [])
        limit_seconds = user.get("limit_seconds")
        tx_bytes_map = dict(user.get("tx_bytes", {}))

        total_delta = 0
        any_active = False
        waiting_baseline = False

        for mac in macs:
            client = active.get(mac)
            if client is None:
                tx_bytes_map.pop(mac, None)
                continue

            if mac not in user.get("devices", {}):
                hostname = client.get("hostname") or ""
                oui = client.get("oui") or ""
                if hostname or oui:
                    store.update_device_info(phone, mac, hostname, oui)

            tx = client.get("tx_bytes") or 0
            prev = tx_bytes_map.get(mac)
            tx_bytes_map[mac] = tx

            if prev is None:
                waiting_baseline = True
                continue

            delta = tx - prev
            if delta < 0:
                continue

            rate = delta / _poll_interval
            if rate >= _active_threshold:
                total_delta += delta
                any_active = True

        if not any_active:
            store.update_usage(phone, 0, tx_bytes_map)
            if waiting_baseline:
                log.info("%s (%s) first seen — waiting for next poll.", user["name"], phone)
            else:
                log.info("%s idle.", user["name"])
            continue

        store.update_usage(phone, _poll_interval, tx_bytes_map)

        seconds_today = user.get("seconds_today", 0) + _poll_interval
        minutes_used = seconds_today // 60

        if limit_seconds is None:
            log.info("%s active — %dm used (unlimited).", user["name"], minutes_used)
            continue

        limit_minutes = limit_seconds // 60
        log.info("%s active — %dm/%dm used.", user["name"], minutes_used, limit_minutes)

        if seconds_today >= limit_seconds:
            log.info("Quota reached for %s — throttling to slow speed.", user["name"])
            for mac in macs:
                gateway.throttle_client(mac)
            # Clear tx_bytes so failsafe gets a clean baseline on next poll
            store.update_guests(lambda g: g[phone].update({"throttled": True, "tx_bytes": {}}) if phone in g else None)


def run() -> None:
    log.info("Monitor thread started (poll interval: %ds).", _poll_interval)
    while True:
        try:
            today = date.today().isoformat()
            guests = store.load_guests()
            needs_reset = any(
                u.get("last_reset_date") != today
                for u in guests.values()
            ) if guests else False

            if needs_reset:
                _run_reset(today)
            else:
                _run_monitor()
        except Exception:
            log.exception("Unhandled error in monitor loop.")

        time.sleep(_poll_interval)


def start() -> None:
    t = threading.Thread(target=run, name="monitor", daemon=True)
    t.start()
