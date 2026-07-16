#!/bin/sh
# LabProbe / Ruijie router agent
# Lightweight one-shot agent intended to be started by cron every minute.
# Runtime state/log/cache are kept under /tmp only.

HUB_URL="http://192.168.5.46:58443/hook/ruijie/devices?token=CHANGE_HOOK_TOKEN"
ROUTER_NAME="BE72Pro"

# Leave empty to parse token from HUB_URL.
LABPROBE_TOKEN=""

DEVICES_INTERVAL_SEC="${DEVICES_INTERVAL_SEC:-45}"
IPV6_FULL_SNAPSHOT_SEC="${IPV6_FULL_SNAPSHOT_SEC:-300}"
HTTP_RETRY_MAX="${HTTP_RETRY_MAX:-3}"
HTTP_CONNECT_TIMEOUT="${HTTP_CONNECT_TIMEOUT:-3}"
HTTP_TOTAL_TIMEOUT="${HTTP_TOTAL_TIMEOUT:-10}"

TMP_DIR="/tmp/labprobe_agent"
LOCK_DIR="/tmp/labprobe_agent.lock"
LOG_FILE="/tmp/labprobe_agent.log"
MAX_LOG_SIZE=262144
KEEP_LOG_SIZE=131072

TMP_FILE="$TMP_DIR/user_list.json"
ERR_FILE="$TMP_DIR/user_list.err"
DEVICE_MACS_FILE="$TMP_DIR/current_macs.txt"
PREV_DEVICE_MACS_FILE="$TMP_DIR/prev_macs.txt"
LAST_DEVICES_TS_FILE="$TMP_DIR/last_devices_push.ts"
LAST_IPV6_HASH_FILE="$TMP_DIR/last_ipv6_hash.txt"
LAST_IPV6_FULL_TS_FILE="$TMP_DIR/last_ipv6_full.ts"
LAST_MODE_FILE="$TMP_DIR/last_ipv6_mode.txt"
PENDING_SNAPSHOT_FILE="$TMP_DIR/pending_snapshot.json"
PENDING_DEVICES_FILE="$TMP_DIR/pending_devices.json"

HUB_BASE="${HUB_URL%%/hook/*}"
PUSH_URL="$HUB_BASE/api/router/push"

mkdir -p "$TMP_DIR"

rotate_log() {
  [ -f "$LOG_FILE" ] || return
  size="$(wc -c < "$LOG_FILE" 2>/dev/null)"
  [ -n "$size" ] || return
  if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
    tail -c "$KEEP_LOG_SIZE" "$LOG_FILE" > "$TMP_DIR/agent.log.tail" 2>/dev/null
    mv "$TMP_DIR/agent.log.tail" "$LOG_FILE" 2>/dev/null
  fi
}

log() {
  rotate_log
  echo "[$(date '+%F %T')] $*" >> "$LOG_FILE"
}

now_ts() {
  date +%s
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

cleanup() {
  rm -f "$TMP_DIR/http_body.$$" "$TMP_DIR/http_resp.$$" "$TMP_DIR/http_err.$$" "$TMP_DIR/snapshot_stable.$$" "$TMP_DIR/snapshot_body.$$"
  if [ -d "$LOCK_DIR" ] && [ "$(cat "$LOCK_DIR/pid" 2>/dev/null)" = "$$" ]; then
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null
  fi
}

acquire_lock() {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$LOCK_DIR/pid"
    trap cleanup EXIT INT TERM
    return 0
  fi

  oldpid="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
  if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
    exit 0
  fi

  rm -rf "$LOCK_DIR" 2>/dev/null
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$LOCK_DIR/pid"
    trap cleanup EXIT INT TERM
    return 0
  fi
  exit 0
}

get_token() {
  if [ -n "$LABPROBE_TOKEN" ]; then
    printf '%s' "$LABPROBE_TOKEN"
    return
  fi
  printf '%s' "$HUB_URL" | sed -n 's/.*[?&]token=\([^&]*\).*/\1/p'
}

sleep_backoff() {
  n="$1"
  case "$n" in
    1) sleep 1 ;;
    2) sleep 2 ;;
    *) sleep 4 ;;
  esac
}

http_post_file_once() {
  url="$1"
  file="$2"
  token="$3"

  if command -v curl >/dev/null 2>&1; then
    if [ -n "$token" ]; then
      curl -sS --connect-timeout "$HTTP_CONNECT_TIMEOUT" -m "$HTTP_TOTAL_TIMEOUT" \
        -X POST "$url" \
        -H "Content-Type: application/json" \
        -H "X-LabProbe-Token: $token" \
        --data-binary "@$file" > "$TMP_DIR/http_resp.$$" 2> "$TMP_DIR/http_err.$$"
    else
      curl -sS --connect-timeout "$HTTP_CONNECT_TIMEOUT" -m "$HTTP_TOTAL_TIMEOUT" \
        -X POST "$url" \
        -H "Content-Type: application/json" \
        --data-binary "@$file" > "$TMP_DIR/http_resp.$$" 2> "$TMP_DIR/http_err.$$"
    fi
    return $?
  fi

  if command -v wget >/dev/null 2>&1; then
    if [ -n "$token" ]; then
      wget -qO "$TMP_DIR/http_resp.$$" \
        --timeout="$HTTP_TOTAL_TIMEOUT" --tries=1 \
        --header="Content-Type: application/json" \
        --header="X-LabProbe-Token: $token" \
        --post-file="$file" "$url" 2> "$TMP_DIR/http_err.$$"
    else
      wget -qO "$TMP_DIR/http_resp.$$" \
        --timeout="$HTTP_TOTAL_TIMEOUT" --tries=1 \
        --header="Content-Type: application/json" \
        --post-file="$file" "$url" 2> "$TMP_DIR/http_err.$$"
    fi
    return $?
  fi

  echo "no curl/wget found" > "$TMP_DIR/http_err.$$"
  return 127
}

http_post_file() {
  url="$1"
  file="$2"
  token="$3"
  attempt=1
  while [ "$attempt" -le "$HTTP_RETRY_MAX" ]; do
    http_post_file_once "$url" "$file" "$token"
    code=$?
    [ "$code" -eq 0 ] && return 0
    [ "$attempt" -lt "$HTTP_RETRY_MAX" ] && sleep_backoff "$attempt"
    attempt=$((attempt + 1))
  done
  return "$code"
}

http_post_json() {
  url="$1"
  token="$2"
  json="$3"
  body="$TMP_DIR/http_body.$$"
  printf '%s' "$json" > "$body"
  http_post_file "$url" "$body" "$token"
}

uci_get() {
  config="$1"
  section="$2"
  opt="$3"
  if command -v uci >/dev/null 2>&1; then
    uci -q get "$config.$section.$opt" 2>/dev/null
  fi
}

get_lan_dev() {
  dev="$(uci_get network lan device)"
  [ -z "$dev" ] && dev="$(uci_get network lan ifname)"
  [ -z "$dev" ] && dev="br-lan"
  printf '%s' "$dev"
}

get_lan_ip() {
  lan_dev="$(get_lan_dev)"
  ip -4 addr show dev "$lan_dev" 2>/dev/null \
    | awk '/inet /{print $2}' \
    | cut -d/ -f1 \
    | head -n1
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
  ip6="$(ip -6 addr show dev "$dev" scope global 2>/dev/null \
    | awk '
      /inet6 / && $0 !~ /tentative/ && $0 !~ /deprecated/ && $0 !~ /temporary/ {
        split($2,a,"/");
        ip=a[1];
        low=tolower(ip);
        if (low !~ /^fe80:/ && low !~ /^fd/ && low !~ /^fc/ && low !~ /^ff/ && low != "::1") {
          print ip;
          exit;
        }
      }')"
  if [ -n "$ip6" ]; then
    printf '%s' "$ip6"
    return
  fi
  ip -6 addr show dev "$dev" scope global 2>/dev/null \
    | awk '
      /inet6 / {
        split($2,a,"/");
        ip=a[1];
        low=tolower(ip);
        if (low !~ /^fe80:/ && low !~ /^fd/ && low !~ /^fc/ && low !~ /^ff/ && low != "::1") {
          print ip;
          exit;
        }
      }'
}

dev_exists() {
  dev="$1"
  [ -n "$dev" ] && ip link show dev "$dev" >/dev/null 2>&1
}

get_candidate_ipv6_devs() {
  get_default_ipv6_dev
  uci_get network wan6 device
  uci_get network wan6 ifname
  uci_get network wan device
  uci_get network wan ifname
  uci_get network wan1_6 device
  uci_get network wan1_6 ifname
  uci_get network wan1 device
  uci_get network wan1 ifname
  get_lan_dev
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

collect_wan6_pairs() {
  default_dev="$(get_default_ipv6_dev)"
  seen_devs=" "
  seen_ips=" "
  primary_done=0
  get_candidate_ipv6_devs | while read dev; do
    [ -z "$dev" ] && continue
    case "$seen_devs" in *" $dev "*) continue ;; esac
    seen_devs="$seen_devs$dev "
    dev_exists "$dev" || continue
    ip6="$(get_global_ipv6_from_dev "$dev" | head -n1 | tr -d '\r\n')"
    [ -z "$ip6" ] && continue
    case "$seen_ips" in *" $ip6 "*) continue ;; esac
    seen_ips="$seen_ips$ip6 "
    primary=false
    if [ "$primary_done" = "0" ] && [ -n "$default_dev" ] && [ "$dev" = "$default_dev" ]; then
      primary=true
      primary_done=1
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
  [ "$count" -eq 0 ] && { printf '[]'; return; }
  idx=0
  printf '['
  echo "$pairs" | while read dev ip6 primary; do
    [ -z "$ip6" ] && continue
    idx=$((idx + 1))
    [ "$primary" = "true" ] && name="主用 WAN" || name="备用 WAN"
    if [ "$primary" != "true" ] && [ "$count" -gt 2 ]; then
      name="备用 WAN $((idx - 1))"
    fi
    [ "$idx" -gt 1 ] && printf ','
    printf '{"name":"%s","ip":"%s","primary":%s}' "$(json_escape "$name")" "$(json_escape "$ip6")" "$primary"
  done
  printf ']'
}

ipv6_addr_lines_for_dev() {
  dev="$1"
  public_only="$2"
  [ -z "$dev" ] && return
  ip -6 -o addr show dev "$dev" scope global 2>/dev/null \
    | awk -v public_only="$public_only" '
      /inet6 / {
        ip=$4; sub(/\/.*/, "", ip);
        low=tolower(ip);
        if (low ~ /^fe80:/ || low ~ /^ff/ || low == "::1" || low ~ /^::ffff:/) next;
        if (public_only == "1" && (low ~ /^fd/ || low ~ /^fc/)) next;
        print ip;
      }'
}

ipv6_addr_list_json_for_dev() {
  dev="$1"
  label="$2"
  public_only="$3"
  ips="$(ipv6_addr_lines_for_dev "$dev" "$public_only" | awk '!seen[$0]++')"
  [ -z "$ips" ] && { printf '[]'; return; }
  printf '['
  idx=0
  echo "$ips" | while read ip6; do
    [ -z "$ip6" ] && continue
    idx=$((idx + 1))
    [ "$idx" -gt 1 ] && printf ','
    primary=false
    [ "$idx" -eq 1 ] && primary=true
    printf '{"name":"%s","ip":"%s","dev":"%s","primary":%s}' \
      "$(json_escape "$label")" "$(json_escape "$ip6")" "$(json_escape "$dev")" "$primary"
  done
  printf ']'
}

router_ipv6_list_json() {
  ip -6 -o addr show scope global 2>/dev/null \
    | awk '
      /inet6 / {
        dev=$2; ip=$4; sub(/\/.*/, "", ip);
        low=tolower(ip);
        if (low ~ /^fe80:/ || low ~ /^ff/ || low == "::1" || low ~ /^::ffff:/) next;
        key=dev "|" ip;
        if (!seen[key]++) print dev, ip;
      }' \
    | awk '
      BEGIN { printf "[" }
      NF>=2 {
        if (n++ > 0) printf ",";
        printf "{\"name\":\"Router IPv6\",\"ip\":\"%s\",\"dev\":\"%s\",\"primary\":%s}", $2, $1, (n==1?"true":"false");
      }
      END { printf "]" }'
}

lan_prefixes_json() {
  lan_dev="$1"
  ip -6 route show dev "$lan_dev" 2>/dev/null \
    | awk '
      $1 ~ /:/ && $1 ~ /\// {
        low=tolower($1);
        if (low ~ /^fe80:/ || low ~ /^ff/ || low == "::1/128" || low ~ /^::ffff:/) next;
        if (!seen[$1]++) print $1;
      }' \
    | awk '
      BEGIN { printf "[" }
      NF>=1 {
        if (n++ > 0) printf ",";
        printf "\"%s\"", $1;
      }
      END { printf "]" }'
}

detect_ipv6_mode() {
  lan_dev="$(get_lan_dev)"
  default_dev="$(get_default_ipv6_dev)"
  lan_ra="$(uci_get dhcp lan ra)"
  lan_dhcpv6="$(uci_get dhcp lan dhcpv6)"
  lan_ndp="$(uci_get dhcp lan ndp)"
  has_global="$(ip -6 -o addr show scope global 2>/dev/null | awk '/inet6 /{print; exit}')"
  [ -z "$has_global" ] && [ -z "$default_dev" ] && { printf 'disabled'; return; }
  if [ "$lan_ra" = "relay" ] || [ "$lan_dhcpv6" = "relay" ] || [ "$lan_ndp" = "relay" ]; then
    printf 'relay'
    return
  fi
  if [ "$lan_ra" = "server" ] || [ "$lan_dhcpv6" = "server" ]; then
    printf 'server'
    return
  fi
  if [ -n "$default_dev" ] && [ "$default_dev" = "$lan_dev" ]; then
    printf 'bridge'
    return
  fi
  printf 'bridge'
}

ipv6_neighbors_json() {
  collected_at="$(date '+%Y-%m-%d %H:%M:%S')"
  ip -6 neigh show 2>/dev/null \
    | awk -v ts="$collected_at" '
      BEGIN { printf "[" }
      {
        ip=$1; dev=""; mac=""; state="";
        for (i=1; i<=NF; i++) {
          if ($i=="dev") dev=$(i+1);
          if ($i=="lladdr") mac=$(i+1);
        }
        state=$NF;
        low=tolower(ip);
        if (mac == "" || ip !~ /:/) next;
        if (low ~ /^fe80:/ || low ~ /^ff/ || low == "::1" || low ~ /^::ffff:/) next;
        if (n++ > 0) printf ",";
        printf "{\"ipv6\":\"%s\",\"mac\":\"%s\",\"dev\":\"%s\",\"state\":\"%s\",\"collectedAt\":\"%s\",\"source\":\"router_ndp\"}", ip, mac, dev, state, ts;
      }
      END { printf "]" }'
}

dhcpv6_leases_json() {
  mode="$1"
  [ "$mode" = "server" ] || { printf '[]'; return; }
  files="/tmp/hosts/odhcpd /tmp/odhcpd.leases /tmp/dhcp.leases"
  for f in $files; do
    [ -s "$f" ] || continue
    awk '
      {
        mac=""; ip="";
        for (i=1; i<=NF; i++) {
          if ($i ~ /^[0-9a-fA-F:][0-9a-fA-F:][:-][0-9a-fA-F:][0-9a-fA-F:]/ && $i ~ /[:-]/ && length($i) >= 17) mac=$i;
          if ($i ~ /:/ && $i !~ /^fe80:/ && $i !~ /^ff/ && $i !~ /^::ffff:/) { split($i,a,"/"); ip=a[1]; }
        }
        if (mac != "" && ip != "") print mac, ip;
      }' "$f"
  done | awk '
    BEGIN { printf "[" }
    NF>=2 {
      key=tolower($1) "|" tolower($2);
      if (seen[key]++) next;
      if (n++ > 0) printf ",";
      printf "{\"mac\":\"%s\",\"ipv6\":\"%s\",\"source\":\"dhcpv6_lease\",\"state\":\"LEASED\"}", $1, $2;
    }
    END { printf "]" }'
}

extract_device_macs() {
  src="$1"
  grep -oi '"mac"[[:space:]]*:[[:space:]]*"[^"]*"' "$src" 2>/dev/null \
    | sed 's/.*"mac"[[:space:]]*:[[:space:]]*"//I; s/".*//' \
    | tr 'A-Z' 'a-z' \
    | sed 's/-/:/g' \
    | sort -u
}

log_device_changes() {
  current="$1"
  [ -f "$PREV_DEVICE_MACS_FILE" ] || { cp "$current" "$PREV_DEVICE_MACS_FILE" 2>/dev/null; return; }
  while read mac; do
    [ -z "$mac" ] && continue
    grep -qx "$mac" "$PREV_DEVICE_MACS_FILE" 2>/dev/null || log "DEVICE_ONLINE mac=$mac"
  done < "$current"
  while read mac; do
    [ -z "$mac" ] && continue
    grep -qx "$mac" "$current" 2>/dev/null || log "DEVICE_OFFLINE mac=$mac"
  done < "$PREV_DEVICE_MACS_FILE"
  cp "$current" "$PREV_DEVICE_MACS_FILE" 2>/dev/null
}

should_push_devices() {
  now="$(now_ts)"
  last="$(cat "$LAST_DEVICES_TS_FILE" 2>/dev/null)"
  [ -z "$last" ] && return 0
  [ $((now - last)) -ge "$DEVICES_INTERVAL_SEC" ]
}

push_ruijie_devices() {
  should_push_devices || return 0

  dev_sta get -m user_list '{"devType":"all","dataType":"timely"}' > "$TMP_FILE" 2>"$ERR_FILE"
  if [ ! -s "$TMP_FILE" ]; then
    log "ERROR empty user list: $(head -c 160 "$ERR_FILE" 2>/dev/null)"
    return 1
  fi

  extract_device_macs "$TMP_FILE" > "$DEVICE_MACS_FILE"
  log_device_changes "$DEVICE_MACS_FILE"

  http_post_file "$HUB_URL" "$TMP_FILE" ""
  code=$?
  if [ "$code" -ne 0 ]; then
    cp "$TMP_FILE" "$PENDING_DEVICES_FILE" 2>/dev/null
    log "ERROR push devices failed code=$code err=$(head -c 160 "$TMP_DIR/http_err.$$" 2>/dev/null)"
    return "$code"
  fi
  rm -f "$PENDING_DEVICES_FILE"
  now_ts > "$LAST_DEVICES_TS_FILE"
  return 0
}

build_snapshot_json() {
  ts="$1"
  lan_ip="$(get_lan_ip)"
  lan_dev="$(get_lan_dev)"
  ipv6_mode="$(detect_ipv6_mode)"
  ipv6_default_if="$(get_default_ipv6_dev)"
  router_wan6="$(get_primary_wan6_ip | tr -d '\r\n')"
  router_wan6_list="$(build_wan6_list_json)"
  router_ipv6_list="$(router_ipv6_list_json)"
  wan_ipv6_list="$(ipv6_addr_list_json_for_dev "$ipv6_default_if" "WAN IPv6" "1")"
  [ "$wan_ipv6_list" = "[]" ] && wan_ipv6_list="$router_wan6_list"
  lan_ipv6_list="$(ipv6_addr_list_json_for_dev "$lan_dev" "LAN IPv6" "0")"
  lan_ipv6_prefixes="$(lan_prefixes_json "$lan_dev")"
  ipv6_neighbors="$(ipv6_neighbors_json)"
  dhcpv6_leases="$(dhcpv6_leases_json "$ipv6_mode")"

  old_mode="$(cat "$LAST_MODE_FILE" 2>/dev/null)"
  if [ -n "$old_mode" ] && [ "$old_mode" != "$ipv6_mode" ]; then
    log "IPV6_MODE_CHANGE old=$old_mode new=$ipv6_mode default_if=$ipv6_default_if"
  fi
  [ "$old_mode" = "$ipv6_mode" ] || echo "$ipv6_mode" > "$LAST_MODE_FILE"

  cat <<EOF
{
  "type":"snapshot",
  "ts":$ts,
  "router":"$(json_escape "$ROUTER_NAME")",
  "lan_ip":"$(json_escape "$lan_ip")",
  "ipv6_mode":"$(json_escape "$ipv6_mode")",
  "ipv6_default_if":"$(json_escape "$ipv6_default_if")",
  "router_wan6":"$(json_escape "$router_wan6")",
  "router_wan6_list":$router_wan6_list,
  "router_ipv6_list":$router_ipv6_list,
  "wan_ipv6_list":$wan_ipv6_list,
  "lan_ipv6_list":$lan_ipv6_list,
  "lan_ipv6_prefixes":$lan_ipv6_prefixes,
  "ipv6_neighbors":$ipv6_neighbors,
  "dhcpv6_leases":$dhcpv6_leases
}
EOF
}

snapshot_hash() {
  file="$1"
  sed 's/"ts":[0-9][0-9]*/"ts":0/' "$file" 2>/dev/null | cksum | awk '{print $1}'
}

should_push_snapshot() {
  body="$1"
  now="$(now_ts)"
  new_hash="$(snapshot_hash "$body")"
  old_hash="$(cat "$LAST_IPV6_HASH_FILE" 2>/dev/null)"
  last_full="$(cat "$LAST_IPV6_FULL_TS_FILE" 2>/dev/null)"
  [ -z "$last_full" ] && last_full=0
  if [ "$new_hash" != "$old_hash" ]; then
    echo "$new_hash" > "$TMP_DIR/next_ipv6_hash.txt"
    return 0
  fi
  if [ $((now - last_full)) -ge "$IPV6_FULL_SNAPSHOT_SEC" ]; then
    echo "$new_hash" > "$TMP_DIR/next_ipv6_hash.txt"
    return 0
  fi
  return 1
}

push_router_snapshot() {
  token="$(get_token)"
  if [ -z "$token" ] || [ "$token" = "CHANGE_HOOK_TOKEN" ]; then
    log "ERROR token not configured, skip router snapshot"
    return 0
  fi

  body="$TMP_DIR/snapshot_body.$$"
  build_snapshot_json "$(now_ts)" > "$body"
  should_push_snapshot "$body" || return 0

  http_post_file "$PUSH_URL" "$body" "$token"
  code=$?
  if [ "$code" -ne 0 ]; then
    cp "$body" "$PENDING_SNAPSHOT_FILE" 2>/dev/null
    log "ERROR push ipv6 snapshot failed code=$code err=$(head -c 160 "$TMP_DIR/http_err.$$" 2>/dev/null)"
    return "$code"
  fi
  rm -f "$PENDING_SNAPSHOT_FILE"
  cat "$TMP_DIR/next_ipv6_hash.txt" 2>/dev/null > "$LAST_IPV6_HASH_FILE"
  now_ts > "$LAST_IPV6_FULL_TS_FILE"
  return 0
}

main() {
  acquire_lock
  push_ruijie_devices
  push_router_snapshot
}

main "$@"
