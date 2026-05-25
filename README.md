# WiFi Captive Portal

A self-hosted captive portal for guest WiFi. Runs on a dedicated Ubuntu VM that acts as the actual router and gateway for the guest network. Guests verify their identity via SMS OTP; new devices require admin approval via Telegram. Approved guests get internet access with a configurable daily time quota — when the quota is exhausted, speed is throttled to a slow rate until midnight.

## How it works

```
Guest device
    │  connects to guest SSID (open, no password)
    │  gets IP from VM's DHCP (dnsmasq)
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

**Quota tracking:** a background monitor polls iptables byte counters every minute. When a guest's daily time quota is reached, Linux `tc` HTB qdiscs throttle their download and upload to a configured slow speed. Counters reset at midnight.

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

### dnsmasq (DHCP only, no DNS)

```
# /etc/dnsmasq.d/captive-portal.conf
interface=eth0
bind-interfaces
port=0
dhcp-range=192.168.21.100,192.168.21.200,12h
dhcp-option=option:router,192.168.21.2
dhcp-option=option:dns-server,8.8.8.8,8.8.4.4
```

### IP forwarding

```
# /etc/sysctl.d/99-captive-portal.conf
net.ipv4.ip_forward=1
```

### Router / UDM Pro (for VLAN21)

- DHCP: **None** (VM handles it)
- Allow internet access: **off** (VM handles NAT)
- mDNS repeater: **on** (so AirPlay/AirPrint works across VLANs)

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
| `ALLOWED_LAN_IPS` | Comma-separated IPs guests may reach on the LAN (printers, TVs, etc.) |
| `LAN_SUBNET` | LAN subnet to gate — all other IPs in this range are blocked |
| `THROTTLE_DOWN_KBPS` | Download speed after quota is hit |
| `THROTTLE_UP_KBPS` | Upload speed after quota is hit |
| `POLL_INTERVAL_SECONDS` | How often the monitor checks usage (default 60) |
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
