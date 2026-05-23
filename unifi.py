import logging

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

_UDM_IP = None
_API_KEY = None
_THROTTLE_DOWN_KBPS = 500
_THROTTLE_UP_KBPS = 250


def init(udm_ip: str, api_key: str, throttle_down_kbps: int = 500, throttle_up_kbps: int = 250) -> None:
    global _UDM_IP, _API_KEY, _THROTTLE_DOWN_KBPS, _THROTTLE_UP_KBPS
    _UDM_IP = udm_ip
    _API_KEY = api_key
    _THROTTLE_DOWN_KBPS = throttle_down_kbps
    _THROTTLE_UP_KBPS = throttle_up_kbps


def _headers() -> dict:
    return {"X-API-Key": _API_KEY}


def _base() -> str:
    return f"https://{_UDM_IP}/proxy/network/api/s/default"


def _oon_base() -> str:
    return f"https://{_UDM_IP}/proxy/network/v2/api/site/default"


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


def throttle_client(mac: str) -> bool:
    payload = {
        "enabled": True,
        "name": f"throttle-{mac}",
        "target_type": "CLIENTS",
        "targets": [{"type": "MAC", "value": mac}],
        "secure": {
            "enabled": False,
            "internet": {"mode": "BLOCKLIST", "everything": True},
        },
        "route": {
            "enabled": False,
            "apps": {"enabled": False, "values": []},
            "domains": {"enabled": False, "values": []},
            "ip_addresses": {"enabled": False, "values": []},
            "regions": {"enabled": False, "values": []},
        },
        "qos": {
            "enabled": True,
            "all_traffic": True,
            "apps": {"enabled": False, "values": []},
            "domains": {"enabled": False, "values": []},
            "ip_addresses": {"enabled": False, "values": []},
            "regions": {"enabled": False, "values": []},
            "mode": "LIMIT",
            "download_limit": {"enabled": True, "limit": _THROTTLE_DOWN_KBPS, "burst": "DISABLED"},
            "upload_limit": {"enabled": True, "limit": _THROTTLE_UP_KBPS, "burst": "DISABLED"},
            "schedule": {"mode": "ALWAYS"},
        },
    }
    try:
        resp = requests.post(
            f"{_oon_base()}/object-oriented-network-config",
            headers=_headers(),
            json=payload,
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        log.info("[%s] Throttle rule created (%d/%d kbps).", mac, _THROTTLE_DOWN_KBPS, _THROTTLE_UP_KBPS)
        return True
    except requests.RequestException as e:
        log.error("throttle_client %s failed: %s", mac, e)
        return False


def unthrottle_client(mac: str) -> bool:
    try:
        resp = requests.get(
            f"{_oon_base()}/object-oriented-network-configs",
            headers=_headers(),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        configs = data if isinstance(data, list) else data.get("data", [])
        rule = next((c for c in configs if c.get("name") == f"throttle-{mac}"), None)
        if not rule:
            log.info("[%s] No throttle rule found — nothing to remove.", mac)
            return True
        rule_id = rule.get("id") or rule.get("_id")
    except requests.RequestException as e:
        log.error("Failed to list OON configs for %s: %s", mac, e)
        return False

    try:
        resp = requests.delete(
            f"{_oon_base()}/object-oriented-network-config/{rule_id}",
            headers=_headers(),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        log.info("[%s] Throttle rule removed.", mac)
        return True
    except requests.RequestException as e:
        log.error("unthrottle_client %s failed: %s", mac, e)
        return False


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
