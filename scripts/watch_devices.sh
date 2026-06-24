#!/bin/sh
# LabProbe Ruijie device event watcher v0.4
# Reads /etc/labprobe/watch_devices.conf line by line, so device names may contain spaces.

HUB_BASE="${1:-__HUB_BASE__}"
HOOK_TOKEN="${2:-__HOOK_TOKEN__}"
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
