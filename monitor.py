import logging
import threading
import time
from datetime import date

import store
import unifi

log = logging.getLogger(__name__)

_poll_interval = 300
_active_threshold = 6250  # bytes/sec


def init(poll_interval: int, active_threshold: int) -> None:
    global _poll_interval, _active_threshold
    _poll_interval = poll_interval
    _active_threshold = active_threshold


def _run_reset(today: str) -> None:
    log.info("Daily reset: unthrottling all users.")
    guests = store.load_guests()
    for phone, user in guests.items():
        if user.get("throttled"):
            for mac in user.get("macs", []):
                unifi.unthrottle_client(mac)
    store.reset_all_daily(today)
    log.info("Daily reset complete.")


def _run_monitor() -> None:
    active = unifi.fetch_active_clients()
    if active is None:
        log.warning("API error — skipping poll.")
        return

    guests = store.load_guests()
    log.info("--- Poll: %d device(s) on network ---", len(active))

    for phone, user in guests.items():
        if user.get("throttled"):
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
                unifi.throttle_client(mac)
            store.set_throttled(phone, True)


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
