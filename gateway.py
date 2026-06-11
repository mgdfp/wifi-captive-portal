"""
gateway.py — replaces unifi.py for the VM-as-router architecture.

Same public API as unifi.py:
  init, authorize_guest, unauthorize_guest, throttle_client,
  unthrottle_client, fetch_active_clients.

Plus: setup_chains() — call once at startup to create iptables chains and tc qdiscs.

Authorization:  per-MAC iptables rules (CAPTIVE_FORWARD / CAPTIVE_REDIRECT chains).
Throttling:     tc HTB on guest NIC egress (download) + tc HTB on an IFB device fed
                from guest NIC ingress (upload), matched by MAC so rules survive IP changes.
                Upload is *shaped* (queued), not policed (dropped), so TLS handshakes and
                push-notification keepalives survive a throttle — they just go slowly.
Accounting:     per-MAC byte counters in CAPTIVE_ACCOUNTING chain.
Client list:    ARP table on the guest NIC.

DHCP/DNS are served by the UDM Pro on VLAN21; the UDM's DHCP hands out this VM's
IP as the default gateway, so clients stay L2-adjacent and their real MACs are
visible here. This VM runs no DHCP server.
"""
import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

_GUEST_IFACE = "eth0"
_WAN_IFACE = "eth1"
_IFB_IFACE = "ifb0"   # intermediate device used to shape guest upload (ingress can't be queued directly)
_THROTTLE_DOWN_KBPS = 100
_THROTTLE_UP_KBPS = 100
_PORTAL_PORT = 80
_ALLOWED_LAN_IPS: list[str] = []   # specific IPs authorized guests may reach on the LAN
_LAN_SUBNET = "192.168.10.0/24"    # everything else in this subnet is blocked

# Remembers the guest IP at authorization time so the download accounting rule
# can be removed even after the client leaves the ARP table.
_authorized_ips: dict[str, str] = {}

# Per-MAC tc minor allocation. Starts at 1000 to avoid the default class 1:999.
# Process-local: _setup_tc() wipes the qdisc on startup, so a fresh counter
# matches the kernel's actual tc state on restart.
_mac_minors: dict[str, int] = {}
_next_minor = 1000


def init(
    guest_iface: str = "eth0",
    wan_iface: str = "eth1",
    throttle_down_kbps: int = 100,
    throttle_up_kbps: int = 100,
    portal_port: int = 80,
    allowed_lan_ips: list[str] | None = None,
    lan_subnet: str = "192.168.10.0/24",
) -> None:
    global _GUEST_IFACE, _WAN_IFACE, _THROTTLE_DOWN_KBPS, _THROTTLE_UP_KBPS
    global _PORTAL_PORT, _ALLOWED_LAN_IPS, _LAN_SUBNET
    _GUEST_IFACE = guest_iface
    _WAN_IFACE = wan_iface
    _THROTTLE_DOWN_KBPS = throttle_down_kbps
    _THROTTLE_UP_KBPS = throttle_up_kbps
    _PORTAL_PORT = portal_port
    _ALLOWED_LAN_IPS = allowed_lan_ips or []
    _LAN_SUBNET = lan_subnet


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    log.debug("run: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _ipt_exists(*args: str, table: str = "filter") -> bool:
    r = subprocess.run(
        ["iptables", "-t", table, "-C"] + list(args),
        capture_output=True, check=False,
    )
    return r.returncode == 0


def _mac_to_ip(mac: str) -> str | None:
    """Current IP for a MAC from the ARP table. Clients are L2-adjacent (this VM
    is their default gateway), so any client we interact with has an entry."""
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            parts = line.split()
            # columns: IP, HW type, Flags, HW addr, Mask, Device
            # Flags 0x0 = incomplete (no reply yet)
            if len(parts) >= 4 and parts[3].lower() == mac and parts[2] != "0x0":
                return parts[0]
    except OSError:
        pass
    return None


def ip_to_mac(ip: str) -> str | None:
    """Look up MAC for a client IP from the ARP table on the guest NIC."""
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            parts = line.split()
            # columns: IP, HW type, Flags, HW addr, Mask, Device
            if len(parts) >= 6 and parts[0] == ip and parts[2] != "0x0" and parts[5] == _GUEST_IFACE:
                return parts[3].lower()
    except OSError:
        pass
    return None


def _tc_ids(mac: str) -> tuple[str, int]:
    """Return (minor_str, prio_int) for a MAC, allocating on first use."""
    minor = _mac_minors.get(mac)
    if minor is None:
        global _next_minor
        minor = _next_minor
        _mac_minors[mac] = minor
        _next_minor += 1
    return str(minor), minor


# ---------------------------------------------------------------------------
# Chain / qdisc setup — call once at startup
# ---------------------------------------------------------------------------

def setup_chains() -> None:
    """
    Create iptables chains and tc qdiscs. Safe to call on restart: managed
    chains are flushed before re-populating so no duplicate rules accumulate.
    Requires root / CAP_NET_ADMIN.
    """
    _setup_iptables()
    _setup_tc()
    log.info("Gateway initialized (guest=%s, wan=%s).", _GUEST_IFACE, _WAN_IFACE)


def restore_state(guests: dict) -> None:
    """Re-apply authorization and throttle rules from persisted guest state.

    Call after setup_chains() so that existing guests are not disrupted by a
    service restart.  authorize_guest() and throttle_client() are idempotent
    (they check for existing rules before inserting), so this is safe to call
    even if some rules survived the restart.
    """
    restored = 0
    throttled = 0
    for phone, user in guests.items():
        if user.get("status") == "blocked":
            continue
        for mac in user.get("devices", {}):
            authorize_guest(mac)
            restored += 1
            if user.get("throttled"):
                throttle_client(mac)
                throttled += 1
    log.info("Restored state: %d authorization(s), %d throttle rule(s).", restored, throttled)


def _setup_iptables() -> None:
    # --- INPUT ---

    # Legacy cleanup: the old architecture ran dnsmasq on this VM with the UDM
    # relaying DHCP to it, which needed a UDP/67 accept. DHCP is now served by
    # the UDM directly on VLAN21 and never reaches this host.
    if _ipt_exists("INPUT", "-i", _GUEST_IFACE, "-p", "udp", "--dport", "67", "-j", "ACCEPT"):
        _run(["iptables", "-D", "INPUT",
              "-i", _GUEST_IFACE, "-p", "udp", "--dport", "67", "-j", "ACCEPT"])

    # --- NAT ---

    # Masquerade all guest traffic leaving on the WAN interface.
    if not _ipt_exists("POSTROUTING", "-o", _WAN_IFACE, "-j", "MASQUERADE", table="nat"):
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING",
              "-o", _WAN_IFACE, "-j", "MASQUERADE"])

    # Skip masquerade for return traffic on LAN-initiated connections. The VM never
    # sees the outbound SYN (it goes UDM→client directly), so conntrack marks these
    # responses INVALID. Without this, the source IP gets rewritten to the VM's LAN IP
    # and the initiating host discards the reply as unexpected.
    if not _ipt_exists("POSTROUTING", "-o", _WAN_IFACE,
                        "-m", "state", "--state", "INVALID", "-j", "RETURN", table="nat"):
        _run(["iptables", "-t", "nat", "-I", "POSTROUTING", "1",
              "-o", _WAN_IFACE,
              "-m", "state", "--state", "INVALID", "-j", "RETURN"])

    # CAPTIVE_REDIRECT: HTTP from the guest NIC lands here.
    # Authorized MACs get a RETURN rule inserted at the front; everyone else
    # hits the REDIRECT at the end and is sent to the captive portal.
    _run(["iptables", "-t", "nat", "-N", "CAPTIVE_REDIRECT"], check=False)
    _run(["iptables", "-t", "nat", "-F", "CAPTIVE_REDIRECT"])
    if not _ipt_exists("PREROUTING", "-i", _GUEST_IFACE, "-p", "tcp", "--dport", "80",
                        "-j", "CAPTIVE_REDIRECT", table="nat"):
        _run(["iptables", "-t", "nat", "-A", "PREROUTING",
              "-i", _GUEST_IFACE, "-p", "tcp", "--dport", "80",
              "-j", "CAPTIVE_REDIRECT"])
    _run(["iptables", "-t", "nat", "-A", "CAPTIVE_REDIRECT",
          "-p", "tcp", "-j", "REDIRECT", "--to-port", str(_PORTAL_PORT)])

    # --- FILTER ---

    # Return traffic for already-established guest sessions (responses from internet
    # going back to guests).  Must be added before CAPTIVE_FORWARD's DROP.
    if not _ipt_exists("FORWARD", "-o", _GUEST_IFACE,
                        "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"):
        _run(["iptables", "-I", "FORWARD", "1",
              "-o", _GUEST_IFACE,
              "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    # Count download bytes (packets going TO guests) for quota tracking.
    # Must be placed before the ESTABLISHED,RELATED accept so byte counters are
    # incremented before the packet is accepted and leaves the chain.
    if not _ipt_exists("FORWARD", "-o", _GUEST_IFACE, "-j", "CAPTIVE_ACCOUNTING"):
        _run(["iptables", "-I", "FORWARD", "1",
              "-o", _GUEST_IFACE, "-j", "CAPTIVE_ACCOUNTING"])

    # CAPTIVE_ACCOUNTING: one RETURN rule per authorized MAC.
    # iptables counts bytes per rule — these counters are read by fetch_active_clients().
    _run(["iptables", "-N", "CAPTIVE_ACCOUNTING"], check=False)
    _run(["iptables", "-F", "CAPTIVE_ACCOUNTING"])
    if not _ipt_exists("FORWARD", "-i", _GUEST_IFACE, "-j", "CAPTIVE_ACCOUNTING"):
        _run(["iptables", "-A", "FORWARD", "-i", _GUEST_IFACE, "-j", "CAPTIVE_ACCOUNTING"])

    # CAPTIVE_FORWARD: authorized MACs ACCEPT, everything else DROP.
    # DNS is allowed for all guests. Clients normally resolve via the UDM on the
    # same VLAN (that traffic never passes this VM), but devices with hardcoded
    # DNS (8.8.8.8 etc.) still need resolution pre-auth so captive portal
    # detection (iOS/Android HTTP probe) actually fires.
    _run(["iptables", "-N", "CAPTIVE_FORWARD"], check=False)
    _run(["iptables", "-F", "CAPTIVE_FORWARD"])
    if not _ipt_exists("FORWARD", "-i", _GUEST_IFACE, "-j", "CAPTIVE_FORWARD"):
        _run(["iptables", "-A", "FORWARD", "-i", _GUEST_IFACE, "-j", "CAPTIVE_FORWARD"])
    _run(["iptables", "-A", "CAPTIVE_FORWARD", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    _run(["iptables", "-A", "CAPTIVE_FORWARD", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
    _run(["iptables", "-A", "CAPTIVE_FORWARD", "-j", "DROP"])

    # CAPTIVE_AUTHORIZED: what an authorized guest is allowed to reach.
    # Specific LAN IPs (printers, TV, etc.) get ACCEPT; all other RFC1918 space
    # is dropped so guests can't reach other VLANs; everything else (internet) passes.
    _run(["iptables", "-N", "CAPTIVE_AUTHORIZED"], check=False)
    _run(["iptables", "-F", "CAPTIVE_AUTHORIZED"])
    for ip in _ALLOWED_LAN_IPS:
        _run(["iptables", "-A", "CAPTIVE_AUTHORIZED", "-d", ip, "-j", "ACCEPT"])
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        _run(["iptables", "-A", "CAPTIVE_AUTHORIZED", "-d", net, "-j", "DROP"])
    _run(["iptables", "-A", "CAPTIVE_AUTHORIZED", "-j", "ACCEPT"])

    # CAPTIVE_VLAN10: gate LAN device access through MAC auth.
    # Traffic to allowed IPs jumps into CAPTIVE_FORWARD (MAC check); everything
    # else on the LAN subnet is dropped before it can reach CAPTIVE_FORWARD.
    _run(["iptables", "-N", "CAPTIVE_VLAN10"], check=False)
    _run(["iptables", "-F", "CAPTIVE_VLAN10"])
    if _LAN_SUBNET and _ALLOWED_LAN_IPS:
        if not _ipt_exists("FORWARD", "-i", _GUEST_IFACE,
                            "-d", _LAN_SUBNET, "-j", "CAPTIVE_VLAN10"):
            _run(["iptables", "-I", "FORWARD",
                  "-i", _GUEST_IFACE, "-d", _LAN_SUBNET, "-j", "CAPTIVE_VLAN10"])
        for ip in _ALLOWED_LAN_IPS:
            _run(["iptables", "-A", "CAPTIVE_VLAN10", "-d", ip, "-j", "CAPTIVE_FORWARD"])
        _run(["iptables", "-A", "CAPTIVE_VLAN10", "-j", "DROP"])

    # Allow return traffic from VLAN21 clients for connections initiated from any LAN
    # (VLAN10, VLAN1, etc.). The outbound SYN goes UDM→client directly (VM never sees
    # it), so conntrack marks the response INVALID. These flows are always INVALID on
    # this VM — conntrack never transitions to ESTABLISHED for them — so INVALID alone
    # is sufficient and avoids accidentally bypassing CAPTIVE_ACCOUNTING for authorized
    # guests' own ESTABLISHED traffic.
    if not _ipt_exists("FORWARD", "-i", _GUEST_IFACE, "-o", _WAN_IFACE,
                        "-m", "state", "--state", "INVALID",
                        "-j", "ACCEPT"):
        _run(["iptables", "-I", "FORWARD", "1",
              "-i", _GUEST_IFACE, "-o", _WAN_IFACE,
              "-m", "state", "--state", "INVALID",
              "-j", "ACCEPT"])


def _setup_tc() -> None:
    # --- Download (guest NIC egress) ---
    # HTB root qdisc on the guest NIC controls download speed per client.
    # Class 1:999 is the default (catch-all) class at full speed.
    # Throttled clients get their own class (1:<minor>) with a rate cap.
    _run(["tc", "qdisc", "del", "dev", _GUEST_IFACE, "root"], check=False)
    _run(["tc", "qdisc", "add", "dev", _GUEST_IFACE, "root", "handle", "1:", "htb", "default", "999"])
    _run(["tc", "class", "add", "dev", _GUEST_IFACE,
          "parent", "1:", "classid", "1:999", "htb", "rate", "1gbit"])
    _run(["tc", "qdisc", "add", "dev", _GUEST_IFACE, "parent", "1:999", "fq_codel"])

    # --- Upload (guest NIC ingress, shaped via IFB) ---
    # A NIC's ingress can only be policed (drop), not queued. Dropping breaks TLS
    # handshakes and push keepalives, so instead we redirect all guest ingress to
    # an IFB device and shape it there with HTB — excess is queued/delayed, not dropped.
    _run(["modprobe", "ifb"], check=False)
    _run(["ip", "link", "add", _IFB_IFACE, "type", "ifb"], check=False)  # no-op if it exists
    _run(["ip", "link", "set", _IFB_IFACE, "up"])

    # HTB on the IFB device mirrors the download side: default 999 = full speed,
    # throttled clients get a 1:<minor> class matched by source MAC.
    _run(["tc", "qdisc", "del", "dev", _IFB_IFACE, "root"], check=False)
    _run(["tc", "qdisc", "add", "dev", _IFB_IFACE, "root", "handle", "1:", "htb", "default", "999"])
    _run(["tc", "class", "add", "dev", _IFB_IFACE,
          "parent", "1:", "classid", "1:999", "htb", "rate", "1gbit"])
    _run(["tc", "qdisc", "add", "dev", _IFB_IFACE, "parent", "1:999", "fq_codel"])

    # Redirect every packet arriving on the guest NIC to the IFB device. IFB shapes
    # it then reinjects it into the normal receive path, so forwarding and the
    # CAPTIVE_ACCOUNTING counters are unaffected.
    _run(["tc", "qdisc", "del", "dev", _GUEST_IFACE, "ingress"], check=False)
    _run(["tc", "qdisc", "add", "dev", _GUEST_IFACE, "handle", "ffff:", "ingress"])
    _run(["tc", "filter", "add", "dev", _GUEST_IFACE, "parent", "ffff:",
          "protocol", "all", "prio", "1", "u32", "match", "u32", "0", "0",
          "action", "mirred", "egress", "redirect", "dev", _IFB_IFACE])


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

def authorize_guest(mac: str) -> bool:
    mac = mac.lower()
    try:
        # Allow forwarding through the gateway — jumps to CAPTIVE_AUTHORIZED which
        # permits only the specific LAN IPs and internet (drops other RFC1918).
        if not _ipt_exists("CAPTIVE_FORWARD", "-m", "mac", "--mac-source", mac, "-j", "CAPTIVE_AUTHORIZED"):
            _run(["iptables", "-I", "CAPTIVE_FORWARD", "1",
                  "-m", "mac", "--mac-source", mac, "-j", "CAPTIVE_AUTHORIZED"])
        # Exempt from portal redirect
        if not _ipt_exists("CAPTIVE_REDIRECT", "-m", "mac", "--mac-source", mac, "-j", "RETURN",
                            table="nat"):
            _run(["iptables", "-t", "nat", "-I", "CAPTIVE_REDIRECT", "1",
                  "-m", "mac", "--mac-source", mac, "-j", "RETURN"])
        # Upload accounting: count bytes sent FROM this MAC.
        if not _ipt_exists("CAPTIVE_ACCOUNTING", "-m", "mac", "--mac-source", mac, "-j", "RETURN"):
            _run(["iptables", "-A", "CAPTIVE_ACCOUNTING",
                  "-m", "mac", "--mac-source", mac, "-j", "RETURN"])
        # Download accounting: count bytes sent TO this guest's IP.
        # Tagged with a comment so _read_accounting_bytes can map the counter back to this MAC.
        ip = _mac_to_ip(mac)
        if ip:
            _authorized_ips[mac] = ip
            dl_args = ["CAPTIVE_ACCOUNTING", "-o", _GUEST_IFACE, "-d", ip,
                       "-m", "comment", "--comment", f"dl:{mac}", "-j", "RETURN"]
            if not _ipt_exists(*dl_args):
                _run(["iptables", "-A"] + dl_args)
        log.info("[%s] Authorized.", mac)
        return True
    except subprocess.CalledProcessError as e:
        log.error("authorize_guest %s: %s", mac, e)
        return False


def unauthorize_guest(mac: str) -> bool:
    mac = mac.lower()
    ok = True
    rules = [
        ("CAPTIVE_FORWARD",    "filter", "CAPTIVE_AUTHORIZED"),
        ("CAPTIVE_REDIRECT",   "nat",    "RETURN"),
        ("CAPTIVE_ACCOUNTING", "filter", "RETURN"),
    ]
    for chain, table, target in rules:
        args = [chain, "-m", "mac", "--mac-source", mac, "-j", target]
        if _ipt_exists(*args, table=table):
            r = _run(["iptables", "-t", table, "-D"] + args, check=False)
            if r.returncode != 0:
                log.error("unauthorize_guest %s: failed to remove from %s", mac, chain)
                ok = False
    # Remove download accounting rule (matched by IP, tagged with mac comment).
    ip = _authorized_ips.pop(mac, None) or _mac_to_ip(mac)
    if ip:
        dl_args = ["CAPTIVE_ACCOUNTING", "-o", _GUEST_IFACE, "-d", ip,
                   "-m", "comment", "--comment", f"dl:{mac}", "-j", "RETURN"]
        if _ipt_exists(*dl_args):
            _run(["iptables", "-D"] + dl_args, check=False)
    if ok:
        log.info("[%s] Authorization revoked.", mac)
    return ok


# ---------------------------------------------------------------------------
# Throttling
# ---------------------------------------------------------------------------

def throttle_client(mac: str) -> bool:
    mac = mac.lower()
    minor, prio = _tc_ids(mac)
    try:
        # Download cap: HTB class + flower filter matched by destination MAC on the guest NIC.
        # fq_codel leaf gives each flow a fair share and bounds latency, so a bulk
        # background flow (iCloud/photo sync) can't starve interactive traffic like
        # messaging at the low throttle rate — without it the pfifo leaf tail-drops.
        _run(["tc", "class", "add", "dev", _GUEST_IFACE,
              "parent", "1:", "classid", f"1:{minor}",
              "htb", "rate", f"{_THROTTLE_DOWN_KBPS}kbit",
                    "ceil", f"{_THROTTLE_DOWN_KBPS}kbit"])
        _run(["tc", "qdisc", "add", "dev", _GUEST_IFACE, "parent", f"1:{minor}", "fq_codel"])
        _run(["tc", "filter", "add", "dev", _GUEST_IFACE,
              "parent", "1:", "protocol", "all", "prio", str(prio),
              "flower", "dst_mac", mac, "flowid", f"1:{minor}"])
        # Upload cap: HTB class + flower filter matched by source MAC on the IFB device.
        # Shaping (queue/delay) rather than policing (drop), plus an fq_codel leaf, keeps
        # interactive connections alive at low speed.
        _run(["tc", "class", "add", "dev", _IFB_IFACE,
              "parent", "1:", "classid", f"1:{minor}",
              "htb", "rate", f"{_THROTTLE_UP_KBPS}kbit",
                    "ceil", f"{_THROTTLE_UP_KBPS}kbit"])
        _run(["tc", "qdisc", "add", "dev", _IFB_IFACE, "parent", f"1:{minor}", "fq_codel"])
        _run(["tc", "filter", "add", "dev", _IFB_IFACE,
              "parent", "1:", "protocol", "all", "prio", str(prio),
              "flower", "src_mac", mac, "flowid", f"1:{minor}"])
        log.info("[%s] Throttled to %d/%d kbps.", mac, _THROTTLE_DOWN_KBPS, _THROTTLE_UP_KBPS)
        return True
    except subprocess.CalledProcessError as e:
        log.error("throttle_client %s: %s", mac, e)
        return False


def unthrottle_client(mac: str) -> bool:
    mac = mac.lower()
    minor, prio = _tc_ids(mac)
    # Errors are expected if rules were never applied or already removed.
    # Download path on the guest NIC.
    _run(["tc", "filter", "del", "dev", _GUEST_IFACE, "parent", "1:", "prio", str(prio)], check=False)
    _run(["tc", "class", "del", "dev", _GUEST_IFACE, "classid", f"1:{minor}"], check=False)
    # Upload path on the IFB device.
    _run(["tc", "filter", "del", "dev", _IFB_IFACE, "parent", "1:", "prio", str(prio)], check=False)
    _run(["tc", "class", "del", "dev", _IFB_IFACE, "classid", f"1:{minor}"], check=False)
    log.info("[%s] Throttle removed.", mac)
    return True


# ---------------------------------------------------------------------------
# Client polling — replaces unifi.fetch_active_clients
# ---------------------------------------------------------------------------

def fetch_active_clients() -> dict | None:
    """
    Return {mac: {"tx_bytes": int, "hostname": str, "oui": str}} for all
    clients with a complete ARP entry on the guest NIC.

    tx_bytes comes from the iptables CAPTIVE_ACCOUNTING counters (upload bytes
    since last setup_chains / chain flush).  The monitor tracks deltas between
    polls, so the absolute origin of the counter doesn't matter.

    hostname is always empty: DHCP (and thus hostname knowledge) lives on the
    UDM now. The OUI prefix serves as the device fingerprint in the admin UI.
    """
    try:
        byte_counts = _read_accounting_bytes()
        clients: dict[str, dict] = {}
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            ip, _, flags, mac, _, iface = parts[:6]
            if iface != _GUEST_IFACE or flags == "0x0":
                continue
            mac = mac.lower()
            clients[mac] = {
                "tx_bytes": byte_counts.get(mac, 0),
                "hostname": "",
                # OUI vendor lookup requires an external DB; use the 3-byte
                # prefix as a device fingerprint for the admin UI instead.
                "oui": mac[:8].upper(),
            }
        return clients
    except Exception as e:
        log.error("fetch_active_clients: %s", e)
        return None


def _read_accounting_bytes() -> dict[str, int]:
    """Parse iptables CAPTIVE_ACCOUNTING counters, return {mac: upload_bytes}."""
    r = _run(
        ["iptables", "-t", "filter", "-L", "CAPTIVE_ACCOUNTING", "-v", "-n", "-x"],
        check=False,
    )
    if r.returncode != 0:
        return {}
    counts: dict[str, int] = {}
    # Upload rule:   pkts bytes RETURN all -- * * 0/0 0/0  MAC aa:bb:cc:dd:ee:ff
    # Download rule: pkts bytes RETURN all -- * eth0 0/0 guest-ip  /* dl:aa:bb:cc:dd:ee:ff */
    mac_re = re.compile(r"^\s*\d+\s+(\d+)\s+RETURN.*MAC\s+([0-9a-f:]{17})", re.IGNORECASE)
    dl_re  = re.compile(r"^\s*\d+\s+(\d+)\s+RETURN.*dl:([0-9a-f:]{17})", re.IGNORECASE)
    for line in r.stdout.splitlines():
        m = mac_re.search(line)
        if m:
            counts[m.group(2).lower()] = int(m.group(1))
            continue
        m = dl_re.search(line)
        if m:
            key = m.group(2).lower()
            counts[key] = counts.get(key, 0) + int(m.group(1))
    return counts
