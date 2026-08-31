#!/usr/bin/env bash
# Fired by systemd OnFailure= when wifi-captive-portal.service enters the
# 'failed' state (i.e. it crash-looped until the start limit was exhausted).
# Sends a Telegram alert so a dead guest portal doesn't go unnoticed the way
# it did 2026-08-19..08-31 (12 days down after a reboot, no one the wiser).
#
# Reads TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID straight out of ../.env — it does
# NOT source the file, because .env has unquoted values with spaces.
set -euo pipefail

UNIT="${1:-wifi-captive-portal.service}"
ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env"

val() { grep -E "^${1}=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-; }
TOKEN="$(val TELEGRAM_BOT_TOKEN)"
CHAT="$(val TELEGRAM_CHAT_ID)"
if [ -z "$TOKEN" ] || [ -z "$CHAT" ]; then
  echo "notify-failure: TELEGRAM_BOT_TOKEN/CHAT_ID not found in $ENV_FILE" >&2
  exit 0
fi

restarts="$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null || echo '?')"
# tail -c can slice a multibyte char; iconv -c drops any resulting invalid
# sequence so the Telegram API doesn't 400 on it and swallow the whole alert.
logtail="$(journalctl -u "$UNIT" -n 20 --no-pager -o cat 2>/dev/null \
            | tail -c 1500 | iconv -c -f UTF-8 -t UTF-8)"

text="🚨 $(hostname): ${UNIT} entered FAILED state — the guest WiFi captive portal is DOWN and systemd has stopped retrying.

Restarts this boot: ${restarts}

Recent log:
${logtail}

Recover with:
  sudo systemctl reset-failed ${UNIT} && sudo systemctl start ${UNIT}"

curl -sS --max-time 15 \
  -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  --data-urlencode "chat_id=${CHAT}" \
  --data-urlencode "text=${text}" >/dev/null \
  && echo "notify-failure: alert sent for ${UNIT}" \
  || { echo "notify-failure: telegram send failed" >&2; exit 1; }
