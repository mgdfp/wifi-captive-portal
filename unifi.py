import logging
import os
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

_UDM_IP = None
_API_KEY = None
_THROTTLE_PROFILE_ID = None


def init(udm_ip: str, api_key: str, throttle_profile_id: str) -> None:
    global _UDM_IP, _API_KEY, _THROTTLE_PROFILE_ID
    _UDM_IP = udm_ip
    _API_KEY = api_key
    _THROTTLE_PROFILE_ID = throttle_profile_id


def _headers() -> dict:
    return {"X-API-Key": _API_KEY}


def _base() -> str:
    return f"https://{_UDM_IP}/proxy/network/api/s/default"


def _stamgr(cmd: str, mac: str) -> bool:
    try:
        resp = requests.post(
            f"{_base()}/cmd/stamgr",
            headers=_headers(),
            json={"cmd": cmd, "mac": mac},
            verify=False,
            timeout=10,
        )
        if resp.status_code == 400:
            log.debug("stamgr %s %s: device not connected, skipping.", cmd, mac)
            return True
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        log.error("stamgr %s %s failed: %s", cmd, mac, e)
        return False


def authorize_guest(mac: str) -> bool:
    ok = _stamgr("authorize-guest", mac)
    if ok:
        log.info("[%s] Guest authorized.", mac)
    return ok


def unauthorize_guest(mac: str) -> bool:
    ok = _stamgr("unauthorize-guest", mac)
    if ok:
        log.info("[%s] Guest authorization revoked.", mac)
    return ok


def _get_user_record(mac: str) -> dict | None:
    try:
        resp = requests.get(
            f"{_base()}/rest/user",
            headers=_headers(),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        return next(
            (u for u in resp.json().get("data", []) if u.get("mac", "").lower() == mac),
            None,
        )
    except requests.RequestException as e:
        log.error("Failed to fetch user record for %s: %s", mac, e)
        return None


def _update_user_record(mac: str, updates: dict) -> bool:
    user = _get_user_record(mac)
    if not user:
        log.warning("No user record for %s — cannot update.", mac)
        return False
    user.update(updates)
    try:
        resp = requests.put(
            f"{_base()}/rest/user/{user['_id']}",
            headers=_headers(),
            json=user,
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        log.error("Failed to update user %s: %s", mac, e)
        return False


def _kick_and_wait(mac: str) -> None:
    time.sleep(5)
    _stamgr("kick-sta", mac)
    deadline = time.time() + 15
    while time.time() < deadline:
        time.sleep(1)
        active = fetch_active_clients()
        if active is None or mac not in active:
            break


def throttle_client(mac: str) -> bool:
    ok = _update_user_record(mac, {"usergroup_id": _THROTTLE_PROFILE_ID})
    if ok:
        log.info("[%s] Throttle profile applied.", mac)
        _kick_and_wait(mac)
    return ok


def unthrottle_client(mac: str) -> bool:
    ok = _update_user_record(mac, {"usergroup_id": ""})
    if ok:
        log.info("[%s] Throttle profile removed.", mac)
        _kick_and_wait(mac)
    return ok


def fetch_active_clients() -> dict | None:
    """Return mac -> client data dict, or None on error."""
    try:
        resp = requests.get(
            f"{_base()}/stat/sta",
            headers=_headers(),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        clients = [c for c in resp.json().get("data", []) if "mac" in c]
        return {c["mac"].lower(): c for c in clients}
    except requests.RequestException as e:
        log.error("Failed to fetch active clients: %s", e)
        return None
