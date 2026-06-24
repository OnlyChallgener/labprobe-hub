#!/bin/sh
# LabProbe Ruijie installer for BE72 / OpenWrt-like systems.
# Usage:
#   sh ruijie_labprobe_install.sh http://192.168.5.46:58443 YOUR_HOOK_TOKEN [pppoe-wan]

HUB_BASE="$1"
HOOK_TOKEN="$2"
WAN_IF="${3:-pppoe-wan}"

if [ -z "$HUB_BASE" ] || [ -z "$HOOK_TOKEN" ]; then
  echo "Usage: sh ruijie_labprobe_install.sh http://192.168.5.46:58443 YOUR_HOOK_TOKEN [pppoe-wan]"
  exit 1
fi

mkdir -p /etc/labprobe

cat > /etc/labprobe/push_devices.sh <<EOF
#!/bin/sh
dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' > /tmp/labprobe_user_list.json 2>/tmp/labprobe_user_list.err
if [ ! -s /tmp/labprobe_user_list.json ]; then
  echo "[LabProbe] empty user list"
  cat /tmp/labprobe_user_list.err 2>/dev/null
  exit 1
fi
curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/devices?token=$HOOK_TOKEN" -H "Content-Type:application/json" --data-binary "@/tmp/labprobe_user_list.json"
echo
EOF

cat > /etc/labprobe/push_router_wan6.sh <<EOF
#!/bin/sh
WAN_IF="$WAN_IF"
OUT="\$(ip -6 -o addr show dev "\$WAN_IF" scope global 2>/dev/null)"
WAN6="\$(printf '%s\n' "\$OUT" | awk '\$0 !~ /deprecated/ && \$0 !~ /temporary/ {print \$4}' | cut -d/ -f1 | grep -Ev '^(fe80:|fd|fc|ff|::1)' | head -n1)"
if [ -z "\$WAN6" ]; then
  WAN6="\$(printf '%s\n' "\$OUT" | awk '{print \$4}' | cut -d/ -f1 | grep -Ev '^(fe80:|fd|fc|ff|::1)' | head -n1)"
fi
if [ -n "\$WAN6" ]; then
  curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/router?token=$HOOK_TOKEN" -H "Content-Type:application/json" -d "{\"wanIf\":\"\$WAN_IF\",\"routerWanIpv6\":\"\$WAN6\",\"status\":\"ok\"}"
else
  curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/router?token=$HOOK_TOKEN" -H "Content-Type:application/json" -d "{\"wanIf\":\"\$WAN_IF\",\"status\":\"check_failed\",\"message\":\"no public IPv6 found\"}"
fi
echo
EOF

chmod +x /etc/labprobe/push_devices.sh /etc/labprobe/push_router_wan6.sh

crontab -l > /tmp/labprobe_cron 2>/dev/null
grep -v "labprobe/push_devices.sh" /tmp/labprobe_cron | grep -v "labprobe/push_router_wan6.sh" > /tmp/labprobe_cron_new
echo "*/1 * * * * /etc/labprobe/push_devices.sh >/tmp/labprobe_devices.log 2>&1" >> /tmp/labprobe_cron_new
echo "*/1 * * * * /etc/labprobe/push_router_wan6.sh >/tmp/labprobe_router_wan6.log 2>&1" >> /tmp/labprobe_cron_new
crontab /tmp/labprobe_cron_new
/etc/init.d/cron enable >/dev/null 2>&1
/etc/init.d/cron restart >/dev/null 2>&1

echo "[LabProbe] installed. Test now:"
/etc/labprobe/push_devices.sh
/etc/labprobe/push_router_wan6.sh

echo "[LabProbe] current crontab:"
crontab -l
