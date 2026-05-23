import logging
import os

import requests

log = logging.getLogger(__name__)

_SID = None
_TOKEN = None
_FROM = None


def init(account_sid: str, auth_token: str, from_number: str) -> None:
    global _SID, _TOKEN, _FROM
    _SID = account_sid
    _TOKEN = auth_token
    _FROM = from_number


def send_otp(to_number: str, code: str) -> bool:
    if not all([_SID, _TOKEN, _FROM, to_number]):
        log.error("Twilio not configured or missing destination number.")
        return False
    try:
        resp = requests.post(
            f"https://api.twilio.com/2010-04-01/Accounts/{_SID}/Messages.json",
            auth=(_SID, _TOKEN),
            data={"From": _FROM, "To": to_number, "Body": f"Your WiFi code: {code}"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        log.info("OTP sent to %s — SID: %s status: %s", to_number, data.get("sid"), data.get("status"))
        return True
    except requests.RequestException as e:
        log.error("Failed to send OTP to %s: %s", to_number, e)
        try:
            log.error("Twilio response: %s", e.response.json())
        except Exception:
            pass
        return False
