#!/usr/bin/env bash
set -euo pipefail

HUB="${HUB:-http://127.0.0.1:58443}"
HOOK_TOKEN="${HOOK_TOKEN:-change-hook-token}"
APP_TOKEN="${APP_TOKEN:-change-app-token}"

curl -X POST "$HUB/hook/lucky?token=$HOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source":"lucky","type":"stun_changed","name":"WireGuard","address":"123.45.67.89:52631"}'

echo
curl -H "Authorization: Bearer $APP_TOKEN" "$HUB/api/events"
echo
