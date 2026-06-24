#!/bin/sh
# Push Ruijie WAN IPv6 to LabProbe Hub.
# Usage: sh ruijie_router_wan6_push.sh http://192.168.5.46:58443 YOUR_HOOK_TOKEN [pppoe-wan]

HUB_BASE="$1"
HOOK_TOKEN="$2"
WAN_IF="${3:-pppoe-wan}"

if [ -z "$HUB_BASE" ] || [ -z "$HOOK_TOKEN" ]; then
  echo "Usage: sh ruijie_router_wan6_push.sh http://192.168.5.46:58443 YOUR_HOOK_TOKEN [pppoe-wan]"
  exit 1
fi

OUT="$(ip -6 -o addr show dev "$WAN_IF" scope global 2>/dev/null)"
WAN6="$(printf '%s\n' "$OUT" | awk '$0 !~ /deprecated/ && $0 !~ /temporary/ {print $4}' | cut -d/ -f1 | grep -Ev '^(fe80:|fd|fc|ff|::1)' | head -n1)"
if [ -z "$WAN6" ]; then
  WAN6="$(printf '%s\n' "$OUT" | awk '{print $4}' | cut -d/ -f1 | grep -Ev '^(fe80:|fd|fc|ff|::1)' | head -n1)"
fi

if [ -n "$WAN6" ]; then
  curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/router?token=$HOOK_TOKEN" \
    -H "Content-Type:application/json" \
    -d "{\"wanIf\":\"$WAN_IF\",\"routerWanIpv6\":\"$WAN6\",\"status\":\"ok\"}"
else
  curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/router?token=$HOOK_TOKEN" \
    -H "Content-Type:application/json" \
    -d "{\"wanIf\":\"$WAN_IF\",\"status\":\"check_failed\",\"message\":\"no public IPv6 found\"}"
fi

echo
