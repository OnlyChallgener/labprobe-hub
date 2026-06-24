#!/bin/sh
# LabProbe: push Ruijie WAN IPv6 from pppoe-wan to Hub.
# Usage: edit HUB_URL with your HOOK_TOKEN, then run this script on the router.

HUB_URL="http://192.168.5.46:58443/hook/ruijie/router?token=YOUR_HOOK_TOKEN"
WAN_IF="pppoe-wan"

WAN6="$(ip -6 -o addr show dev "$WAN_IF" scope global 2>/dev/null | awk '$0 !~ /deprecated/ {print $4}' | cut -d/ -f1 | grep -v '^fe80:' | grep -v '^fd' | grep -v '^fc' | grep -v '^ff' | head -n1)"

if [ -z "$WAN6" ]; then
  echo "[LabProbe] no public IPv6 found on $WAN_IF"
  exit 1
fi

curl -sS -m 8 -X POST "$HUB_URL&wanIf=$WAN_IF&routerWanIpv6=$WAN6"
echo
