#!/bin/sh
# LabProbe / Ruijie router push script
# v0.7.6-router-wan6-list-no-nas-mix-keep-nas
#
# 功能：
# 1. 保留原来的锐捷终端列表推送：
#    dev_sta get -m user_list ... -> /hook/ruijie/devices
#
# 2. 推送路由器快照：
#    LAN IP / 路由 WAN6 / 多 WAN6 列表 -> /api/router/push
#
# 3. 已兼容：
#    普通路由：wan / wan6 / pppoe-wan
#    多 WAN：wan1 / wan1_6 / wan1-6 / wan1.6 / pppoe-wan1
#    桥接 / AP：br-lan / br-wan
#
# 4. APP 普通页面只需要显示：
#    路由 WAN6：2409:xxxx...
#    多 WAN 时显示：主用 WAN / 备用 WAN
#    不需要显示 br-lan / br-wan 等底层接口名。
#
# 你通常只需要改下面 3 行。

HUB_URL="http://192.168.5.46:58443/hook/ruijie/devices?token=CHANGE_HOOK_TOKEN"
ROUTER_NAME="BE72Pro"

# 留空会自动从 HUB_URL 里解析 token；也可以直接写死：
# LABPROBE_TOKEN="你的token"
LABPROBE_TOKEN=""

TMP_FILE="/tmp/labprobe_ruijie_user_list.json"
ERR_FILE="/tmp/labprobe_ruijie_err.log"
LOG_FILE="/tmp/labprobe_ruijie_push.log"

HUB_BASE="${HUB_URL%%/hook/*}"
PUSH_URL="$HUB_BASE/api/router/push"

log() {
  echo "[$(date '+%F %T')] $*" >> "$LOG_FILE"
}

now_ts() {
  date +%s
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

get_token() {
  if [ -n "$LABPROBE_TOKEN" ]; then
    printf '%s' "$LABPROBE_TOKEN"
    return
  fi
  printf '%s' "$HUB_URL" | sed -n 's/.*[?&]token=\([^&]*\).*/\1/p'
}

http_post_file() {
  url="$1"
  file="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -sS -m 8 \
      -X POST "$url" \
      -H "Content-Type: application/json" \
      --data-binary "@$file"
    return $?
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO- \
      --timeout=8 \
      --header="Content-Type: application/json" \
      --post-file="$file" \
      "$url"
    return $?
  fi

  log "ERROR: no curl/wget found"
  return 1
}

http_post_json() {
  url="$1"
  token="$2"
  json="$3"

  if command -v curl >/dev/null 2>&1; then
    curl -sS -m 8 \
      -X POST "$url" \
      -H "Content-Type: application/json" \
      -H "X-LabProbe-Token: $token" \
      -d "$json"
    return $?
  fi

  if command -v wget >/dev/null 2>&1; then
    tmp="/tmp/labprobe_push_body.json"
    printf '%s' "$json" > "$tmp"
    wget -qO- \
      --timeout=8 \
      --header="Content-Type: application/json" \
      --header="X-LabProbe-Token: $token" \
      --post-file="$tmp" \
      "$url"
    rm -f "$tmp"
    return $?
  fi

  log "ERROR: no curl/wget found"
  return 1
}

get_lan_ip() {
  ip -4 addr show dev br-lan 2>/dev/null \
    | awk '/inet /{print $2}' \
    | cut -d/ -f1 \
    | head -n1
}

get_public_ipv4() {
  if command -v curl >/dev/null 2>&1; then
    v="$(curl -4 -s --max-time 3 https://api.ipify.org 2>/dev/null)"
    [ -n "$v" ] && printf '%s' "$v" && return
    curl -4 -s --max-time 3 https://ipv4.icanhazip.com 2>/dev/null | tr -d '\r\n'
  fi
}

get_public_ipv6() {
  if command -v curl >/dev/null 2>&1; then
    v="$(curl -6 -s --max-time 3 https://api64.ipify.org 2>/dev/null)"
    [ -n "$v" ] && printf '%s' "$v" && return
    curl -6 -s --max-time 3 https://v6.ident.me 2>/dev/null | tr -d '\r\n'
  fi
}

get_default_ipv6_dev() {
  ip -6 route show default 2>/dev/null \
    | awk '{
        for (i=1;i<=NF;i++) {
          if ($i=="dev") {
            print $(i+1);
            exit;
          }
        }
      }'
}

get_global_ipv6_from_dev() {
  dev="$1"
  [ -z "$dev" ] && return

  # 第一轮：避开 tentative / deprecated / temporary，优先拿稳定公网 IPv6。
  ip6="$(ip -6 addr show dev "$dev" scope global 2>/dev/null \
    | awk '
      /inet6 / && $0 !~ /tentative/ && $0 !~ /deprecated/ && $0 !~ /temporary/ {
        split($2,a,"/");
        ip=a[1];
        if (ip !~ /^fe80:/ && ip !~ /^fd/ && ip !~ /^fc/) {
          print ip;
          exit;
        }
      }')"

  if [ -n "$ip6" ]; then
    printf '%s' "$ip6"
    return
  fi

  # 第二轮：放宽 temporary，只要是公网 IPv6 就取。
  ip -6 addr show dev "$dev" scope global 2>/dev/null \
    | awk '
      /inet6 / {
        split($2,a,"/");
        ip=a[1];
        if (ip !~ /^fe80:/ && ip !~ /^fd/ && ip !~ /^fc/) {
          print ip;
          exit;
        }
      }'
}

uci_get() {
  section="$1"
  opt="$2"
  if command -v uci >/dev/null 2>&1; then
    uci -q get "network.$section.$opt" 2>/dev/null
  fi
}

get_candidate_ipv6_devs() {
  # 默认 IPv6 路由接口最优先，它就是当前主用出口。
  get_default_ipv6_dev

  # UCI 常见配置。
  uci_get wan6 device
  uci_get wan6 ifname
  uci_get wan device
  uci_get wan ifname

  uci_get wan1_6 device
  uci_get wan1_6 ifname
  uci_get wan1 device
  uci_get wan1 ifname

  uci_get lan device
  uci_get lan ifname

  # 常见接口兜底。
  echo wan6
  echo wan
  echo wan1_6
  echo wan1
  echo wan1-6
  echo wan1.6
  echo pppoe-wan
  echo pppoe-wan1
  echo br-wan
  echo br-wan1
  echo br-lan
  echo br0
  echo eth0
  echo eth1
}

dev_exists() {
  dev="$1"
  [ -n "$dev" ] && ip link show dev "$dev" >/dev/null 2>&1
}

collect_wan6_pairs() {
  # 输出格式：
  # dev ip primary_flag
  default_dev="$(get_default_ipv6_dev)"
  seen_devs=" "
  seen_ips=" "
  primary_done=0

  get_candidate_ipv6_devs | while read dev; do
    [ -z "$dev" ] && continue

    case "$seen_devs" in
      *" $dev "*) continue ;;
    esac
    seen_devs="$seen_devs$dev "

    dev_exists "$dev" || continue

    ip6="$(get_global_ipv6_from_dev "$dev" | head -n1 | tr -d '\r\n')"
    [ -z "$ip6" ] && continue

    # 同一个 IPv6 同时出现在 br-wan / br-lan 时只保留一次。
    case "$seen_ips" in
      *" $ip6 "*) continue ;;
    esac
    seen_ips="$seen_ips$ip6 "

    primary=false
    if [ "$primary_done" = "0" ]; then
      if [ -n "$default_dev" ] && [ "$dev" = "$default_dev" ]; then
        primary=true
        primary_done=1
      fi
    fi

    echo "$dev $ip6 $primary"
  done
}

get_primary_wan6_ip() {
  pairs="$(collect_wan6_pairs)"
  echo "$pairs" | awk '$3=="true"{print $2; found=1; exit} END{if(!found){}}'
  if [ -z "$(echo "$pairs" | awk '$3=="true"{print $2; exit}')" ]; then
    echo "$pairs" | awk 'NF>=2{print $2; exit}'
  fi
}

build_wan6_list_json() {
  pairs="$(collect_wan6_pairs)"
  count="$(echo "$pairs" | awk 'NF>=2{c++} END{print c+0}')"

  if [ "$count" -eq 0 ]; then
    printf '[]'
    return
  fi

  idx=0
  printf '['
  echo "$pairs" | while read dev ip6 primary; do
    [ -z "$ip6" ] && continue
    idx=$((idx + 1))

    if [ "$primary" = "true" ]; then
      name="主用 WAN"
    else
      name="备用 WAN"
      # 多个备用时加序号：备用 WAN 1 / 备用 WAN 2
      if [ "$count" -gt 2 ]; then
        n=$((idx - 1))
        name="备用 WAN $n"
      fi
    fi

    [ "$idx" -gt 1 ] && printf ','

    # 注意：普通页面不展示 dev。日志里仍记录 dev 便于排查。
    printf '{"name":"%s","ip":"%s","primary":%s}' \
      "$(json_escape "$name")" \
      "$(json_escape "$ip6")" \
      "$primary"
  done
  printf ']'
}

push_ruijie_devices() {
  dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' > "$TMP_FILE" 2>"$ERR_FILE"

  if [ ! -s "$TMP_FILE" ]; then
    log "ERROR: empty user list"
    cat "$ERR_FILE" >> "$LOG_FILE"
    return 1
  fi

  http_post_file "$HUB_URL" "$TMP_FILE" >/tmp/labprobe_ruijie_post.out 2>>"$LOG_FILE"
  code=$?
  if [ "$code" -ne 0 ]; then
    log "ERROR: push ruijie devices failed, code=$code"
  else
    log "OK: pushed ruijie devices"
  fi
  return "$code"
}

push_router_snapshot() {
  token="$(get_token)"
  ts="$(now_ts)"
  lan_ip="$(get_lan_ip)"
  router_wan6="$(get_primary_wan6_ip | tr -d '\r\n')"
  router_wan6_list="$(build_wan6_list_json)"

  json="{
    \"type\":\"snapshot\",
    \"ts\":$ts,
    \"router\":\"$(json_escape "$ROUTER_NAME")\",
    \"lan_ip\":\"$(json_escape "$lan_ip")\",
    \"router_wan6\":\"$(json_escape "$router_wan6")\",
    \"router_wan6_list\":$router_wan6_list
  }"

  if [ -z "$token" ] || [ "$token" = "CHANGE_HOOK_TOKEN" ]; then
    log "WARN: token not configured, skip router snapshot"
    return 0
  fi

  http_post_json "$PUSH_URL" "$token" "$json" >/tmp/labprobe_snapshot_post.out 2>>"$LOG_FILE"
  code=$?
  if [ "$code" -ne 0 ]; then
    log "ERROR: push router snapshot failed, code=$code"
  else
    log "OK: pushed router snapshot router_wan6=$router_wan6 list=$router_wan6_list"
  fi
  return "$code"
}

main() {
  # 终端列表推送失败时，不阻断快照推送。
  push_ruijie_devices
  push_router_snapshot
  echo
}

main "$@"
