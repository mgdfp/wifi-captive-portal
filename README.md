# WiFi Captive Portal

A self-hosted captive portal for guest WiFi. Runs on a dedicated Ubuntu VM that acts as the default gateway for the guest network — the UDM Pro handles DHCP and DNS, but hands out the VM's IP as the gateway, so all guest traffic flows through the VM for authorization and throttling. Guests verify their identity via SMS OTP; new devices require admin approval via Telegram. Approved guests get internet access with a configurable daily time quota — when the quota is exhausted, speed is throttled to a slow rate until midnight.

## How it works

```
Guest device
    │  connects to guest SSID (open, no password)
    │  gets IP + DNS from UDM Pro DHCP
    │  default gateway = the VM (DHCP gateway override)
    ▼
Ubuntu VM (eth0 = guest NIC, eth1 = uplink)
    │  iptables intercepts HTTP → redirects to portal
    │  guest enters name + Norwegian phone number
    │  SMS OTP sent via Twilio
    │  new users: Telegram bot asks admin to approve
    │  on approval: iptables ACCEPT rule added for MAC
    │  traffic masqueraded out through eth1
    ▼
Internet
```

The split of responsibilities keeps the flaky-prone services (DHCP, DNS, VLANs) on the device built for them, while the VM stays a simple next-hop doing iptables + tc. Because clients are L2-adjacent to the VM, their real MAC addresses are visible — which the whole auth model depends on.

**Kill switch:** if the VM ever misbehaves, change the DHCP Gateway IP override on the UDM back to `192.168.21.1` — guests instantly get a normal, fully-UDM network while you debug.

**Quota tracking:** a background monitor polls iptables byte counters every `POLL_INTERVAL_SECONDS` (default 300). When a guest's daily time quota is reached, Linux `tc` HTB qdiscs throttle their download and upload to a configured slow speed. Counters reset at midnight.

**LAN access:** specific LAN IPs (printers, Apple TV, etc.) can be whitelisted. All other private IP ranges are blocked — guests cannot reach other VLANs or internal hosts.

## Requirements

- Ubuntu 24.04 VM with two NICs
  - `eth0`: guest-facing (static IP, e.g. `192.168.21.2/24`)
  - `eth1`: uplink to LAN/internet (DHCP or static)
- [uv](https://docs.astral.sh/uv/) for Python dependency management
- Twilio account (SMS OTP)
- Telegram bot token + chat ID (admin approval)

## Network setup

### VM (netplan)

```yaml
# /etc/netplan/50-cloud-init.yaml
network:
  ethernets:
    eth0:
      dhcp4: false
      addresses: [192.168.21.2/24]
    eth1:
      dhcp4: true
  version: 2
```

### IP forwarding

```
# /etc/sysctl.d/99-captive-portal.conf
net.ipv4.ip_forward=1
```

### Router / UDM Pro (for VLAN21)

- DHCP: **Server** mode, range e.g. `192.168.21.100–192.168.21.200`
- DHCP **Gateway IP override: `192.168.21.2`** (the VM) — this is what routes guest traffic through the portal
- DHCP DNS: **Auto** (the UDM itself serves DNS)
- Allow internet access: **off** — guests can only reach the internet via the VM, which NATs out its uplink
- mDNS repeater: **on** (so AirPlay/AirPrint works across VLANs)
- Firewall rule: **drop NEW connections from the VLAN21 subnet to other VLANs/RFC1918**. Legitimate guest traffic never matches (it egresses via the VM, masqueraded from the VM's uplink IP); this only stops a client that manually sets its gateway to `192.168.21.1` to bypass the portal.

## Installation

```bash
git clone https://github.com/mgdfp/wifi-captive-portal
cd wifi-captive-portal
cp .env.example .env
# edit .env with your credentials
sudo bash install.sh
sudo systemctl start wifi-captive-portal
```

## Configuration

All configuration is in `.env`. Key settings:

| Variable | Description |
|---|---|
| `GUEST_IFACE` | Guest-facing NIC (default `eth0`) |
| `WAN_IFACE` | Uplink NIC (default `eth1`) |
| `PORTAL_HOST` | VM's IP on the guest network (default `192.168.21.2`) |
| `ALLOWED_LAN_IPS` | Comma-separated LAN targets guests may reach: `ip` for all ports (printers, TVs) or `ip:port` for a single TCP/UDP port (e.g. `192.168.10.100:8123` for Home Assistant) |
| `LAN_SUBNET` | LAN subnet to gate — all other IPs in this range are blocked |
| `THROTTLE_DOWN_KBPS` | Download speed after quota is hit |
| `THROTTLE_UP_KBPS` | Upload speed after quota is hit |
| `POLL_INTERVAL_SECONDS` | How often the monitor checks usage (default 300). Time quota is credited in whole intervals, so this is also the quota granularity |
| `WIFI_NETWORK_NAME` | Shown in the SMS sent when a blocked user is approved |

## Admin management (Telegram bot)

Send commands to the bot from your configured chat:

| Command | Description |
|---|---|
| `/list` | Show all users, usage, and quota |
| `/modify` | Manage a user — change quota, block, reset, or delete |

When a new guest registers, the bot sends an approval request with quota options (5 min, 15 min, 30 min, 1h, 2h, 4h, or unlimited). Tap to approve or deny.

## Architecture

| File | Purpose |
|---|---|
| `gateway.py` | iptables chains, tc throttling, ARP client discovery |
| `app.py` | Flask portal: OTP flow, session management, API endpoints |
| `monitor.py` | Background thread: quota tracking, throttle, daily reset |
| `telegram_bot.py` | Bot polling, approval callbacks, admin commands |
| `sms.py` | Twilio SMS wrapper |
| `store.py` | JSON guest database (`data/guests.json`) |
| `gunicorn.conf.py` | Gunicorn config (1 worker, gthread, starts monitor + bot) |

### iptables chains

```
PREROUTING (nat)
  └─ CAPTIVE_REDIRECT: authorized MACs → RETURN, others → REDIRECT :80

FORWARD
  ├─ CAPTIVE_ACCOUNTING: byte counters per MAC (upload) + per IP (download)
  ├─ CAPTIVE_VLAN10: gate traffic to allowed LAN IPs through MAC auth
  └─ CAPTIVE_FORWARD: authorized MACs → CAPTIVE_AUTHORIZED, others → DROP
       └─ CAPTIVE_AUTHORIZED: allowed LAN IPs → ACCEPT, RFC1918 → DROP, internet → ACCEPT
```

## Guest flow

1. Connect to WiFi → browser opens captive portal automatically
2. Enter name and Norwegian mobile number → receive SMS code
3. Enter SMS code
   - **Returning user** (phone known): immediately authorized
   - **New user**: waiting page shown, admin receives Telegram notification
4. Admin taps a quota option in Telegram → guest is authorized, portal closes
5. When daily quota is exhausted: speed throttled to `THROTTLE_DOWN/UP_KBPS`
6. Quota resets at midnight
