import logging
import threading
import time
from datetime import date

import sms
import store
import gateway
import telegram_bot

log = logging.getLogger(__name__)

_poll_interval = 300
_active_threshold = 6250       # bytes/sec
_low_balance_limit: float | None = None

# MACs we've already alerted about (throttle could not be applied) — avoids
# one Telegram message per poll. Cleared on daily reset.
_throttle_alerted: set[str] = set()


def init(poll_interval: int, active_threshold: int, twilio_low_balance: float | None = None) -> None:
    global _poll_interval, _active_threshold, _low_balance_limit
    _poll_interval = poll_interval
    _active_threshold = active_threshold
    _low_balance_limit = twilio_low_balance


def _run_reset(today: str) -> None:
    log.info("Daily reset: unthrottling all users.")
    _throttle_alerted.clear()
    guests = store.load_guests()
    for phone, user in guests.items():
        if user.get("status") == "blocked":
            continue
        if user.get("throttled"):
            for mac in user.get("devices", {}):
                gateway.unthrottle_client(mac)
                gateway.authorize_guest(mac)  # idempotent; self-heals any lost auth rules
    store.reset_all_daily(today)
    log.info("Daily reset complete.")

    if _low_balance_limit is not None:
        balance = sms.get_balance()
        if balance is not None and balance < _low_balance_limit:
            telegram_bot.send(
                f"⚠️ Twilio-saldo lav: ${balance:.2f} (grense: ${_low_balance_limit:.2f}). Husk å fylle på!"
            )
            log.warning("Twilio balance $%.2f is below threshold $%.2f.", balance, _low_balance_limit)


def _reconcile_throttle(user: dict) -> None:
    """Make sure every device of a throttled user actually has tc rules.

    Replaces the old failsafe kick: with tc enforced locally on this VM,
    "throttle not holding" can only mean the rules are missing (lost tc state,
    device registered without them) — so re-apply instead of de-authorizing.
    If applying fails, alert the admin once rather than kicking the guest.
    """
    for mac in user.get("devices", {}):
        mac = mac.lower()
        if gateway.throttle_is_applied(mac):
            continue
        gateway.unthrottle_client(mac)  # clear any partial state before re-applying
        if gateway.throttle_client(mac):
            log.info("Re-applied missing throttle for %s (%s).", user["name"], mac)
        elif mac not in _throttle_alerted:
            _throttle_alerted.add(mac)
            telegram_bot.send(
                f"⚠️ Klarte ikke å throttle {user['name']} ({mac}) — sjekk gatewayen."
            )


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
            _reconcile_throttle(user)
            continue

        macs = list(user.get("devices", {}).keys())
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

            device_info = user.get("devices", {}).get(mac, {})
            if not device_info.get("hostname") and not device_info.get("oui"):
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
            # tx_bytes isn't tracked while throttled; clear it so the next
            # unthrottle starts from a clean baseline.
            store.update_guests(lambda g: g[phone].update({"throttled": True, "tx_bytes": {}}) if phone in g else None)
            if user.get("notify_throttle_sms", True):
                if not sms.send_sms(phone, "Din daglige internettkvote er brukt opp. Hastigheten er redusert. Kvoten nullstilles ved midnatt."):
                    log.warning("[%s] Failed to send throttle notification SMS.", phone)
                telegram_bot.send(f"🐢 {user['name']} ({phone}) har nådd kvoten og er throttlet.")


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
