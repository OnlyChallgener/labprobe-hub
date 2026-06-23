#!/usr/bin/env sh
set -e

HOOK_TOKEN="${HOOK_TOKEN:-change-this-hook-token}"
HUB_URL="${HUB_URL:-http://127.0.0.1:58443}"

curl -X POST "$HUB_URL/hook/lucky?token=$HOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source":"lucky",
    "type":"stun_changed",
    "name":"WireGuard",
    "address":"123.45.67.89:52631"
  }'
