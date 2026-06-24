#!/bin/sh
# LabProbe Ruijie installer v0.3 for BE72 / OpenWrt-like systems.
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

cat > /etc/labprobe/push_devices.sh <<'PUSH_DEVICES_EOF'
#!/bin/sh
HUB_BASE="__HUB_BASE__"
HOOK_TOKEN="__HOOK_TOKEN__"
dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' > /tmp/labprobe_user_list.json 2>/tmp/labprobe_user_list.err
if [ ! -s /tmp/labprobe_user_list.json ]; then
  echo "[LabProbe] empty user list"
  cat /tmp/labprobe_user_list.err 2>/dev/null
  exit 1
fi
curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/devices?token=$HOOK_TOKEN" -H "Content-Type:application/json" --data-binary "@/tmp/labprobe_user_list.json"
echo
PUSH_DEVICES_EOF

cat > /etc/labprobe/push_router_wan6.sh <<'PUSH_WAN_EOF'
#!/bin/sh
HUB_BASE="__HUB_BASE__"
HOOK_TOKEN="__HOOK_TOKEN__"
WAN_IF="__WAN_IF__"
OUT="$(ip -6 -o addr show dev "$WAN_IF" scope global 2>/dev/null)"
WAN6="$(printf '%s\n' "$OUT" | awk '$0 !~ /deprecated/ && $0 !~ /temporary/ {print $4}' | cut -d/ -f1 | grep -Ev '^(fe80:|fd|fc|ff|::1)' | head -n1)"
if [ -z "$WAN6" ]; then
  WAN6="$(printf '%s\n' "$OUT" | awk '{print $4}' | cut -d/ -f1 | grep -Ev '^(fe80:|fd|fc|ff|::1)' | head -n1)"
fi
if [ -n "$WAN6" ]; then
  curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/router?token=$HOOK_TOKEN" -H "Content-Type:application/json" -d "{\"wanIf\":\"$WAN_IF\",\"routerWanIpv6\":\"$WAN6\",\"status\":\"ok\"}"
else
  curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/router?token=$HOOK_TOKEN" -H "Content-Type:application/json" -d "{\"wanIf\":\"$WAN_IF\",\"status\":\"check_failed\",\"message\":\"no public IPv6 found\"}"
fi
echo
PUSH_WAN_EOF

cat > /etc/labprobe/watch_devices.conf <<'WATCH_CONF_EOF'
# MAC|显示名称|离线容错次数；5秒检测一次：24约2分钟，6约30秒
24:1a:e6:bb:16:d9|华为Mate60|24
da:1f:85:0c:19:fc|iQOO Neo3|6
WATCH_CONF_EOF

cat > /etc/labprobe/watch_devices.sh <<'WATCH_EOF'
#!/bin/sh
# LabProbe Ruijie device event watcher v0.4
# Reads /etc/labprobe/watch_devices.conf line by line, so device names may contain spaces.

HUB_BASE="__HUB_BASE__"
HOOK_TOKEN="__HOOK_TOKEN__"
CONF="/etc/labprobe/watch_devices.conf"
STATE_DIR="/tmp/labprobe_watch_state"
LOG_FILE="/tmp/labprobe_watch.log"
RESP_FILE="/tmp/labprobe_watch_last_resp.log"
CHECK_INTERVAL=5
RETRY_MAX=5

mkdir -p "$STATE_DIR"

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
safe_key() { printf '%s' "$1" | tr 'A-Z:' 'a-z_'; }
getv() { printf '%s' "$1" | grep -o '"'"$2"'":"[^"]*"' | head -n1 | cut -d'"' -f4; }

push_event() {
  TYPE="$1"; MAC="$2"; NAME="$3"; IP="$4"; RSSI="$5"; BAND="$6"; RATE="$7"; SSID="$8"; DURATION="$9"
  NOW="$(date '+%Y-%m-%d %H:%M:%S')"
  JSON="{\"source\":\"ruijie_watch\",\"type\":\"$TYPE\",\"mac\":\"$MAC\",\"name\":\"$(json_escape "$NAME")\",\"ip\":\"$(json_escape "$IP")\",\"lastIp\":\"$(json_escape "$IP")\",\"rssi\":\"$(json_escape "$RSSI")\",\"lastRssi\":\"$(json_escape "$RSSI")\",\"band\":\"$(json_escape "$BAND")\",\"lastBand\":\"$(json_escape "$BAND")\",\"rxrate\":\"$(json_escape "$RATE")\",\"lastRxrate\":\"$(json_escape "$RATE")\",\"ssid\":\"$(json_escape "$SSID")\",\"lastSsid\":\"$(json_escape "$SSID")\",\"onlineDurationSec\":\"$DURATION\",\"time\":\"$NOW\"}"
  RESP="$(curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/device_event?token=$HOOK_TOKEN" -H "Content-Type:application/json" -d "$JSON" 2>&1)"
  echo "$RESP" > "$RESP_FILE"
  echo "$NOW $TYPE $NAME $MAC $IP $RSSI $BAND $RATE => $RESP" >> "$LOG_FILE"
}

if [ ! -s "$CONF" ]; then
  cat > "$CONF" <<'EOF'
# MAC|显示名称|离线容错次数；5秒检测一次：24约2分钟，6约30秒
24:1a:e6:bb:16:d9|华为Mate60|24
da:1f:85:0c:19:fc|iQOO Neo3|6
EOF
fi

while true; do
  RAW_JSON="$(dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' 2>/dev/null)"
  while IFS='|' read -r MAC NAME THRESHOLD; do
    [ -z "$MAC" ] && continue
    case "$MAC" in \#*) continue ;; esac
    [ -z "$THRESHOLD" ] && THRESHOLD=6
    KEY="$(safe_key "$MAC")"
    STATUS_FILE="$STATE_DIR/$KEY.status"; FAIL_FILE="$STATE_DIR/$KEY.fail"; START_FILE="$STATE_DIR/$KEY.start"; LAST_FILE="$STATE_DIR/$KEY.last"
    STATUS="$(cat "$STATUS_FILE" 2>/dev/null)"; [ -z "$STATUS" ] && STATUS=0
    FAIL="$(cat "$FAIL_FILE" 2>/dev/null)"; [ -z "$FAIL" ] && FAIL=0
    LINE="$(printf '%s' "$RAW_JSON" | sed 's/},{/}\n{/g' | grep -i "\"mac\":\"$MAC\"" | head -n1)"
    if [ -n "$LINE" ]; then
      IP="$(getv "$LINE" userIp)"; RSSI="$(getv "$LINE" rssi)"; BAND="$(getv "$LINE" band)"; RATE="$(getv "$LINE" rxrate)"; SSID="$(getv "$LINE" ssid)"
      if [ "$STATUS" != "1" ]; then
        RETRY=0
        while { [ -z "$RSSI" ] || [ -z "$RATE" ]; } && [ "$RETRY" -lt "$RETRY_MAX" ]; do
          sleep 2
          RAW_JSON_RETRY="$(dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' 2>/dev/null)"
          LINE="$(printf '%s' "$RAW_JSON_RETRY" | sed 's/},{/}\n{/g' | grep -i "\"mac\":\"$MAC\"" | head -n1)"
          IP="$(getv "$LINE" userIp)"; RSSI="$(getv "$LINE" rssi)"; BAND="$(getv "$LINE" band)"; RATE="$(getv "$LINE" rxrate)"; SSID="$(getv "$LINE" ssid)"
          RETRY=$((RETRY + 1))
        done
        date +%s > "$START_FILE"; echo 1 > "$STATUS_FILE"; echo 0 > "$FAIL_FILE"; echo "$IP|$RSSI|$BAND|$RATE|$SSID" > "$LAST_FILE"
        push_event "device_online" "$MAC" "$NAME" "$IP" "$RSSI" "$BAND" "$RATE" "$SSID" "0"
      else
        echo 0 > "$FAIL_FILE"; echo "$IP|$RSSI|$BAND|$RATE|$SSID" > "$LAST_FILE"
      fi
    else
      if [ "$STATUS" = "1" ]; then
        FAIL=$((FAIL + 1)); echo "$FAIL" > "$FAIL_FILE"
        if [ "$FAIL" -ge "$THRESHOLD" ]; then
          START_TS="$(cat "$START_FILE" 2>/dev/null)"; [ -z "$START_TS" ] && START_TS="$(date +%s)"
          NOW_TS="$(date +%s)"; DURATION=$((NOW_TS - START_TS - CHECK_INTERVAL * THRESHOLD)); [ "$DURATION" -lt 0 ] && DURATION=0
          LAST="$(cat "$LAST_FILE" 2>/dev/null)"; IP="$(echo "$LAST" | cut -d'|' -f1)"; RSSI="$(echo "$LAST" | cut -d'|' -f2)"; BAND="$(echo "$LAST" | cut -d'|' -f3)"; RATE="$(echo "$LAST" | cut -d'|' -f4)"; SSID="$(echo "$LAST" | cut -d'|' -f5)"
          push_event "device_offline" "$MAC" "$NAME" "$IP" "$RSSI" "$BAND" "$RATE" "$SSID" "$DURATION"
          echo 0 > "$STATUS_FILE"; echo 0 > "$FAIL_FILE"
        fi
      fi
    fi
  done < "$CONF"
  sleep "$CHECK_INTERVAL"
done

WATCH_EOF

# Fill placeholders.
sed -i "s#__HUB_BASE__#$HUB_BASE#g; s#__HOOK_TOKEN__#$HOOK_TOKEN#g; s#__WAN_IF__#$WAN_IF#g" /etc/labprobe/push_devices.sh /etc/labprobe/push_router_wan6.sh /etc/labprobe/watch_devices.sh
chmod +x /etc/labprobe/push_devices.sh /etc/labprobe/push_router_wan6.sh /etc/labprobe/watch_devices.sh

# cron: keep snapshot and router WAN sync. watcher is long-running daemon.
crontab -l > /tmp/labprobe_cron 2>/dev/null
grep -v "labprobe/push_devices.sh" /tmp/labprobe_cron | grep -v "labprobe/push_router_wan6.sh" > /tmp/labprobe_cron_new
echo "*/1 * * * * /etc/labprobe/push_devices.sh >/tmp/labprobe_devices.log 2>&1" >> /tmp/labprobe_cron_new
echo "*/1 * * * * /etc/labprobe/push_router_wan6.sh >/tmp/labprobe_router_wan6.log 2>&1" >> /tmp/labprobe_cron_new
crontab /tmp/labprobe_cron_new
/etc/init.d/cron enable >/dev/null 2>&1
/etc/init.d/cron restart >/dev/null 2>&1

# rc.local daemon start.
killall -9 watch_devices.sh 2>/dev/null
ps | grep '/etc/labprobe/watch_devices.sh' | grep -v grep | awk '{print $1}' | xargs kill -9 2>/dev/null
if ! grep -q "/etc/labprobe/watch_devices.sh" /etc/rc.local 2>/dev/null; then
  sed -i '/exit 0/i /etc/labprobe/watch_devices.sh > /tmp/labprobe_watch.log 2>&1 &' /etc/rc.local
fi
/etc/labprobe/watch_devices.sh > /tmp/labprobe_watch.log 2>&1 &

# initial push
/etc/labprobe/push_devices.sh
/etc/labprobe/push_router_wan6.sh

echo "[LabProbe] installed v0.3. current crontab:"
crontab -l
echo "[LabProbe] watcher process:"
ps | grep '/etc/labprobe/watch_devices.sh' | grep -v grep
