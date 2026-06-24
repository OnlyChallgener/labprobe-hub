#!/bin/sh
# LabProbe Ruijie device event watcher v0.3
# Usage: sh watch_devices.sh http://192.168.5.46:58443 YOUR_HOOK_TOKEN

HUB_BASE="$1"
HOOK_TOKEN="$2"

if [ -z "$HUB_BASE" ] || [ -z "$HOOK_TOKEN" ]; then
  echo "Usage: sh watch_devices.sh http://192.168.5.46:58443 YOUR_HOOK_TOKEN"
  exit 1
fi

# 关注设备：MAC|名称。需要加设备就在这里追加，空格分隔。
DEVICES="24:1a:e6:bb:16:d9|华为Mate60 da:1f:85:0c:19:fc|iQOO Neo3"
CHECK_INTERVAL=5
RETRY_MAX=5

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

mac_key() {
  printf '%s' "$1" | tr 'A-Z' 'a-z' | tr ':' '_'
}

get_field() {
  # $1=line $2=field
  printf '%s' "$1" | grep -oE '"'$2'":"[^"]*"' | head -n1 | cut -d'"' -f4
}

post_event() {
  TYPE="$1"; NAME="$2"; MAC="$3"; IP="$4"; RSSI="$5"; BAND="$6"; RATE="$7"; SSID="$8"; ONLINE_SINCE="$9"; OFFLINE_AT="${10}"; DURATION_SEC="${11}"
  TIME_NOW="$(date '+%Y-%m-%d %H:%M:%S')"
  [ -z "$ONLINE_SINCE" ] && ONLINE_SINCE="$TIME_NOW"
  JSON="{\"type\":\"$TYPE\",\"source\":\"ruijie_watch\",\"time\":\"$TIME_NOW\",\"name\":\"$(json_escape "$NAME")\",\"mac\":\"$MAC\",\"ip\":\"$(json_escape "$IP")\",\"lastIp\":\"$(json_escape "$IP")\",\"rssi\":\"$(json_escape "$RSSI")\",\"band\":\"$(json_escape "$BAND")\",\"rxrate\":\"$(json_escape "$RATE")\",\"ssid\":\"$(json_escape "$SSID")\",\"onlineSince\":\"$ONLINE_SINCE\",\"offlineAt\":\"$OFFLINE_AT\",\"onlineDurationSec\":\"$DURATION_SEC\"}"
  curl -sS -m 8 -X POST "$HUB_BASE/hook/ruijie/device_event?token=$HOOK_TOKEN" -H "Content-Type:application/json" -d "$JSON" >/tmp/labprobe_watch_last_resp.log 2>&1
}

# 初始化状态变量
for dev in $DEVICES; do
  MAC="$(printf '%s' "$dev" | cut -d'|' -f1)"
  KEY="$(mac_key "$MAC")"
  eval "is_online_$KEY=0"
  eval "fail_count_$KEY=0"
  eval "start_time_$KEY=0"
  eval "start_text_$KEY=''"
  eval "last_ip_$KEY=''"
  eval "last_rssi_$KEY=''"
  eval "last_band_$KEY=''"
  eval "last_rate_$KEY=''"
  eval "last_ssid_$KEY=''"
done

sleep 2
while true; do
  RAW_JSON="$(dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' 2>/dev/null)"
  for dev in $DEVICES; do
    MAC="$(printf '%s' "$dev" | cut -d'|' -f1)"
    NAME="$(printf '%s' "$dev" | cut -d'|' -f2)"
    KEY="$(mac_key "$MAC")"
    eval "STATUS=\$is_online_$KEY"
    eval "F_COUNT=\$fail_count_$KEY"
    eval "S_TIME=\$start_time_$KEY"
    eval "S_TEXT=\$start_text_$KEY"
    eval "LAST_IP=\$last_ip_$KEY"
    eval "LAST_RSSI=\$last_rssi_$KEY"
    eval "LAST_BAND=\$last_band_$KEY"
    eval "LAST_RATE=\$last_rate_$KEY"
    eval "LAST_SSID=\$last_ssid_$KEY"

    D_LINE="$(printf '%s' "$RAW_JSON" | sed 's/},{/}\n{/g' | grep -i "$MAC" | head -n1)"

    if [ -n "$D_LINE" ]; then
      IP="$(get_field "$D_LINE" userIp)"
      RSSI="$(get_field "$D_LINE" rssi)"
      BAND="$(get_field "$D_LINE" band)"
      RATE="$(get_field "$D_LINE" rxrate)"
      SSID="$(get_field "$D_LINE" ssid)"

      # 上线瞬间锐捷可能还没补齐 rssi/rxrate，重试几次锁定更完整字段。
      if [ "$STATUS" -eq 0 ]; then
        RETRY=0
        while { [ -z "$RSSI" ] || [ -z "$RATE" ]; } && [ "$RETRY" -lt "$RETRY_MAX" ]; do
          sleep 2
          RAW_JSON_RETRY="$(dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' 2>/dev/null)"
          D_LINE="$(printf '%s' "$RAW_JSON_RETRY" | sed 's/},{/}\n{/g' | grep -i "$MAC" | head -n1)"
          RSSI="$(get_field "$D_LINE" rssi)"
          RATE="$(get_field "$D_LINE" rxrate)"
          BAND="$(get_field "$D_LINE" band)"
          SSID="$(get_field "$D_LINE" ssid)"
          IP="$(get_field "$D_LINE" userIp)"
          RETRY=$((RETRY + 1))
        done
        NOW_SEC="$(date +%s)"
        NOW_TEXT="$(date '+%Y-%m-%d %H:%M:%S')"
        eval "start_time_$KEY=$NOW_SEC"
        eval "start_text_$KEY='$NOW_TEXT'"
        eval "is_online_$KEY=1"
        post_event "device_online" "$NAME" "$MAC" "$IP" "$RSSI" "$BAND" "$RATE" "$SSID" "$NOW_TEXT" "" "0"
      fi

      eval "fail_count_$KEY=0"
      eval "last_ip_$KEY='$IP'"
      eval "last_rssi_$KEY='$RSSI'"
      eval "last_band_$KEY='$BAND'"
      eval "last_rate_$KEY='$RATE'"
      eval "last_ssid_$KEY='$SSID'"
    else
      [ "$NAME" = "华为Mate60" ] && THRESHOLD=24 || THRESHOLD=6
      if [ "$STATUS" -eq 1 ]; then
        NEW_F=$((F_COUNT + 1))
        eval "fail_count_$KEY=$NEW_F"
        if [ "$NEW_F" -ge "$THRESHOLD" ]; then
          NOW_SEC="$(date +%s)"
          OFFLINE_TEXT="$(date '+%Y-%m-%d %H:%M:%S')"
          TOL=$((CHECK_INTERVAL * THRESHOLD))
          DURATION=$((NOW_SEC - S_TIME - TOL))
          [ "$DURATION" -lt 0 ] && DURATION=0
          post_event "device_offline" "$NAME" "$MAC" "$LAST_IP" "$LAST_RSSI" "$LAST_BAND" "$LAST_RATE" "$LAST_SSID" "$S_TEXT" "$OFFLINE_TEXT" "$DURATION"
          eval "is_online_$KEY=0"
          eval "fail_count_$KEY=0"
        fi
      fi
    fi
  done
  sleep "$CHECK_INTERVAL"
done
