#!/bin/sh

# 改成你的绿联 NAS Hub 地址和 HOOK_TOKEN
HUB_URL="http://192.168.5.46:58443/hook/ruijie/devices?token=CHANGE_HOOK_TOKEN"
TMP_FILE="/tmp/labprobe_ruijie_user_list.json"
ERR_FILE="/tmp/labprobe_ruijie_err.log"

dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' > "$TMP_FILE" 2>"$ERR_FILE"

if [ ! -s "$TMP_FILE" ]; then
  echo "[LabProbe] empty user list"
  cat "$ERR_FILE"
  exit 1
fi

if command -v curl >/dev/null 2>&1; then
  curl -sS -m 8 \
    -X POST "$HUB_URL" \
    -H "Content-Type: application/json" \
    --data-binary "@$TMP_FILE"
else
  wget -qO- \
    --timeout=8 \
    --header="Content-Type: application/json" \
    --post-file="$TMP_FILE" \
    "$HUB_URL"
fi

echo
