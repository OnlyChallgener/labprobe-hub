#!/bin/sh
# LabProbe Rust Agent installer for adapted Ruijie routers, compatible with BusyBox ash.
# Usage: wget -O /tmp/labprobe-install.sh URL && sh /tmp/labprobe-install.sh

set -u

ACTION="${1:-install}"
INSTALL_DIR="/etc/labprobe"
BIN="/usr/bin/labrelay"
CONFIG="$INSTALL_DIR/agent.json"
RELAY_CONFIG="$INSTALL_DIR/relay.json"
INIT_SCRIPT="/etc/init.d/labprobe"
TMP_BIN="/tmp/labrelay.new"
TMP_SUM="/tmp/labrelay.new.sha256"
UPDATE_ROOT="${LABPROBE_UPDATE_ROOT:-https://lab.net86.dynv6.net:27772}"
AGENT_BASE="${UPDATE_ROOT%/}/agent"
NONINTERACTIVE="${LABPROBE_NONINTERACTIVE:-0}"

case "$ACTION" in
  install|upgrade|repair|configure|uninstall) ;;
  *) echo "[LabProbe] ERROR: 不支持的操作：$ACTION（可用：install/upgrade/repair/configure/uninstall）" >&2; exit 1 ;;
esac

say() { echo "[LabProbe] $*"; }
fail() { say "ERROR: $*" >&2; exit 1; }
ask_yes() {
  [ "$NONINTERACTIVE" = "1" ] && return 0
  prompt="$1"; default="${2:-Y}"; printf "%s " "$prompt"; read answer || answer=""
  [ -z "$answer" ] && answer="$default"
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

need_root() { [ "$(id -u 2>/dev/null)" = "0" ] || fail "请使用 root 运行"; }

detect_arch() {
  case "$(uname -m 2>/dev/null)" in
    aarch64|arm64) ARCH="arm64" ;;
    *) fail "Rust Agent 仅支持已适配锐捷路由器的 ARM64 架构：$(uname -m 2>/dev/null)" ;;
  esac
}

check_router() {
  command -v dev_sta >/dev/null 2>&1 || fail "未检测到锐捷 dev_sta"
  command -v ip >/dev/null 2>&1 || fail "缺少 ip 命令"
  if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
  elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
  else
    fail "缺少 curl 或 wget，无法下载安装包"
  fi
  command -v sha256sum >/dev/null 2>&1 || fail "缺少 sha256sum，无法校验下载"
  [ -r /etc/rc.common ] || fail "未检测到兼容的锐捷/OpenWrt 服务环境"
  free_kb="$(df -k /etc 2>/dev/null | awk 'NR==2 {print $4}')"
  [ -n "$free_kb" ] || free_kb=0
  [ "$free_kb" -ge 8192 ] || fail "/etc 可用空间不足 8MB"
}

probe_hub() {
  candidate="$1"; [ -n "$candidate" ] || return 1
  case "$candidate" in http://*|https://*) base="$candidate" ;; *) base="http://$candidate:58443" ;; esac
  say "正在探测 Hub：$base"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --silent --show-error --connect-timeout 1 --max-time 2 \
      --output /tmp/labprobe-discovery.json "$base/.well-known/labprobe" 2>/dev/null || return 1
  else
    wget -O /tmp/labprobe-discovery.json -T 2 "$base/.well-known/labprobe" >/dev/null 2>&1 || return 1
  fi
  grep -q '"ok"[[:space:]]*:[[:space:]]*true' /tmp/labprobe-discovery.json || return 1
  HUB_URL="$base"; return 0
}

discover_hub() {
  HUB_URL="${HUB_URL:-}"
  rm -f /tmp/labprobe-found-hub
  [ -n "$HUB_URL" ] && probe_hub "$HUB_URL" && return 0
  if [ -f "$CONFIG" ]; then
    saved="$(sed -n 's/.*"hubUrl"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | head -n1)"
    [ -n "$saved" ] && probe_hub "$saved" && return 0
  fi
  gateway="$(ip route show default 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="via"){print $(i+1);exit}}')"
  probe_hub "$gateway" && return 0
  ip neigh show 2>/dev/null | awk '{print $1}' | head -n 32 | while read address; do
    probe_hub "$address" && { echo "$HUB_URL" >/tmp/labprobe-found-hub; break; }
  done
  [ -f /tmp/labprobe-found-hub ] && HUB_URL="$(cat /tmp/labprobe-found-hub)"
  [ -n "$HUB_URL" ] || fail "未自动发现 Hub；可先设置 HUB_URL=http://192.168.1.20:58443 后重试"
}

download_visible() {
  url="$1"
  output="$2"
  title="$3"
  rm -f "$output"
  say "开始下载$title"
  say "地址：$url"
  if [ "$DOWNLOADER" = "curl" ]; then
    # progress-bar在有Content-Length时显示百分比、总大小和实时速度；
    # 无Content-Length时curl仍持续显示已传输大小和速度。
    if ! curl --progress-bar --fail --location --show-error \
      --connect-timeout 15 --max-time 1800 --speed-limit 1 --speed-time 30 \
      --retry 2 --retry-delay 1 \
      --output "$output" "$url"; then
      rm -f "$output"
      fail "$title下载失败（curl已返回错误），请检查网络、URL和发布文件"
    fi
  else
    # 不使用-q，保留BusyBox wget原生百分比、大小和KB/s进度输出。
    if ! wget -T 30 -O "$output" "$url"; then
      rm -f "$output"
      fail "$title下载失败（wget已返回错误），请检查网络、URL和发布文件"
    fi
  fi
  [ -s "$output" ] || { rm -f "$output"; fail "$title下载完成但文件为空"; }
  bytes="$(wc -c < "$output" 2>/dev/null | tr -d ' ')"
  [ -n "$bytes" ] || bytes="未知"
  say "$title下载完成：$bytes 字节"
}

download_binary() {
  filename="labrelay-linux-$ARCH"
  url="$AGENT_BASE/$filename"
  rm -f "$TMP_BIN" "$TMP_SUM"
  download_visible "$url" "$TMP_BIN" " Rust Agent"
  download_visible "$AGENT_BASE/checksums.txt" "$TMP_SUM" " SHA256校验文件"
  say "正在校验 Rust Agent SHA256"
  expected="$(awk -v name="$filename" '$2 == name || $2 == "*" name {print $1; exit}' "$TMP_SUM")"
  actual="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "SHA256校验失败：下载文件可能不完整或已被修改"
  say "SHA256校验通过：$actual"
  chmod 0755 "$TMP_BIN"
}

backup_old() {
  rm -f /tmp/labprobe-cron.old /tmp/labprobe-cron.new
  stamp="$(date +%Y%m%d%H%M%S)"; BACKUP="$INSTALL_DIR/backups/$stamp"; mkdir -p "$BACKUP"
  HAD_OLD_BIN=0; HAD_OLD_CONFIG=0; HAD_OLD_RELAY=0; HAD_OLD_INIT=0
  if [ -f "$BIN" ]; then HAD_OLD_BIN=1; cp "$BIN" "$BACKUP/labrelay" 2>/dev/null || fail "备份旧 Rust Agent 失败"; fi
  if [ -f "$CONFIG" ]; then HAD_OLD_CONFIG=1; cp "$CONFIG" "$BACKUP/agent.json" 2>/dev/null || fail "备份旧 Agent 配置失败"; fi
  if [ -f "$RELAY_CONFIG" ]; then HAD_OLD_RELAY=1; cp "$RELAY_CONFIG" "$BACKUP/relay.json" 2>/dev/null || fail "备份旧 Relay 配置失败"; fi
  if [ -f "$INIT_SCRIPT" ]; then HAD_OLD_INIT=1; cp "$INIT_SCRIPT" "$BACKUP/init.labprobe" 2>/dev/null || fail "备份旧开机脚本失败"; fi
}

prune_backups() {
  # Keep exactly the backup created for the current install/upgrade.
  for dir in "$INSTALL_DIR"/backups/*; do
    [ -d "$dir" ] || continue
    [ "$dir" = "$BACKUP" ] && continue
    rm -rf "$dir"
  done
}

cleanup_legacy() {
  crontab -l >/tmp/labprobe-cron.old 2>/dev/null || true
  grep -v '/etc/labprobe/.*\(push_devices\|push_router_wan6\|watch_devices\|ruijie_push_to_labprobe\|labrelay_agent\)\.sh' /tmp/labprobe-cron.old >/tmp/labprobe-cron.new 2>/dev/null || true
  crontab /tmp/labprobe-cron.new 2>/dev/null || true
  for service in labrelay_agent labrelay; do
    old_init="/etc/init.d/$service"
    if [ -f "$old_init" ]; then
      [ -x "$old_init" ] && "$old_init" stop >/dev/null 2>&1 || true
      [ -x "$old_init" ] && "$old_init" disable >/dev/null 2>&1 || true
      mv "$old_init" "$BACKUP/$service.legacy-init"
    fi
  done
  # The unified service has not started yet, so any remaining labrelay process
  # belongs to a legacy init/script and must not survive the migration.
  killall labrelay >/dev/null 2>&1 || true
  for old_pid in $(ps w 2>/dev/null | awk '/\/etc\/labprobe\/(labrelay_agent|ruijie_push_to_labprobe|push_devices|push_router_wan6|watch_devices)\.sh/ && !/awk/ {print $1}'); do
    kill "$old_pid" >/dev/null 2>&1 || true
  done
  for old in push_devices.sh push_router_wan6.sh watch_devices.sh ruijie_push_to_labprobe.sh labrelay_agent.sh; do
    [ -f "$INSTALL_DIR/$old" ] && mv "$INSTALL_DIR/$old" "$BACKUP/$old.legacy"
  done
  rm -rf /tmp/labprobe_agent.lock /tmp/labprobe_watch_state
  say "旧 cron、Shell Agent、旧 init 和残留进程已停用，业务由统一 Rust Agent 接管"
}

write_service() {
  cat >"$INIT_SCRIPT" <<'EOF'
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

start_service() {
  mkdir -p /tmp/labprobe
  procd_open_instance relay
  procd_set_param command /usr/bin/labrelay daemon --config /etc/labprobe/relay.json --socket /tmp/labrelay.sock --state /tmp/labprobe/relay-state.json
  procd_set_param respawn 3600 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance

  procd_open_instance agent
  procd_set_param command /usr/bin/labrelay agent --config /etc/labprobe/agent.json
  procd_set_param respawn 3600 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOF
  chmod 0755 "$INIT_SCRIPT"
}

rollback() {
  say "安装失败，正在回滚"
  if [ "${HAD_OLD_BIN:-0}" = "1" ]; then cp "$BACKUP/labrelay" "$BIN"; else rm -f "$BIN"; fi
  if [ "${HAD_OLD_CONFIG:-0}" = "1" ]; then cp "$BACKUP/agent.json" "$CONFIG"; else rm -f "$CONFIG"; fi
  if [ "${HAD_OLD_RELAY:-0}" = "1" ]; then cp "$BACKUP/relay.json" "$RELAY_CONFIG"; else rm -f "$RELAY_CONFIG"; fi
  if [ "${HAD_OLD_INIT:-0}" = "1" ]; then cp "$BACKUP/init.labprobe" "$INIT_SCRIPT"; chmod 0755 "$INIT_SCRIPT"; else rm -f "$INIT_SCRIPT"; fi
  [ -f /tmp/labprobe-cron.old ] && crontab /tmp/labprobe-cron.old 2>/dev/null || true
  for legacy in "$BACKUP"/*.legacy; do
    [ -f "$legacy" ] || continue
    old_name="$(basename "$legacy" .legacy)"
    mv "$legacy" "$INSTALL_DIR/$old_name"
  done
  for legacy_init in "$BACKUP"/*.legacy-init; do
    [ -f "$legacy_init" ] || continue
    old_name="$(basename "$legacy_init" .legacy-init)"
    mv "$legacy_init" "/etc/init.d/$old_name"
    chmod 0755 "/etc/init.d/$old_name"
    "/etc/init.d/$old_name" enable >/dev/null 2>&1 || true
    "/etc/init.d/$old_name" start >/dev/null 2>&1 || true
  done
  "$INIT_SCRIPT" restart >/dev/null 2>&1 || true
  exit 1
}

uninstall_agent() {
  need_root
  ask_yes "是否卸载 LabProbe Rust Agent？[Y/n]" Y || exit 0
  [ -x "$INIT_SCRIPT" ] && "$INIT_SCRIPT" stop >/dev/null 2>&1
  [ -x "$INIT_SCRIPT" ] && "$INIT_SCRIPT" disable >/dev/null 2>&1
  rm -f "$INIT_SCRIPT" "$BIN"
  say "已卸载程序；配置和备份仍保留在 $INSTALL_DIR"
  exit 0
}

[ "$ACTION" = "uninstall" ] && uninstall_agent
need_root
ask_yes "是否安装 LabProbe Rust Agent？[Y/n]" Y || exit 0
detect_arch
check_router
discover_hub
say "自动发现 Hub：$HUB_URL"
ask_yes "自动发现的 Hub 是否正确？[Y/n]" Y || fail "已取消；请设置 HUB_URL 后重试"

HOOK_TOKEN_INPUT="${HOOK_TOKEN:-}"
if [ "$ACTION" = "install" ] || [ "$ACTION" = "configure" ] || ! grep -q '"hookToken"[[:space:]]*:' "$CONFIG" 2>/dev/null; then
  if [ -z "$HOOK_TOKEN_INPUT" ]; then
    printf "请输入 Hub HOOK_TOKEN："; read HOOK_TOKEN_INPUT || HOOK_TOKEN_INPUT=""
  fi
  [ -n "$HOOK_TOKEN_INPUT" ] || fail "HOOK_TOKEN 不能为空"
fi

say "架构=$ARCH，Hub=$HUB_URL，将安装采集、事件、IPv6、端口映射、重试、日志和开机自启"
ask_yes "确认安装？[Y/n]" Y || exit 0

mkdir -p "$INSTALL_DIR/backups" /tmp/labprobe
backup_old
prune_backups
download_binary
[ -x "$INIT_SCRIPT" ] && "$INIT_SCRIPT" stop >/dev/null 2>&1 || true
cp "$TMP_BIN" "$BIN" || rollback
chmod 0755 "$BIN"
[ -f "$RELAY_CONFIG" ] || echo '{"version":1,"rules":[]}' >"$RELAY_CONFIG"
chmod 600 "$RELAY_CONFIG"

if [ -n "$HOOK_TOKEN_INPUT" ]; then
  ROUTER_NAME="${PRIMARY_ROUTER_NAME:-$(hostname 2>/dev/null || echo router)}"
  [ -n "$ROUTER_NAME" ] || ROUTER_NAME="router"
  "$BIN" configure --hub "$HUB_URL" --hook-token "$HOOK_TOKEN_INPUT" --name "$ROUTER_NAME" --config "$CONFIG" || rollback
fi
[ -s "$CONFIG" ] || rollback
chmod 600 "$CONFIG"
cleanup_legacy
write_service
"$INIT_SCRIPT" enable >/dev/null 2>&1 || rollback
"$INIT_SCRIPT" start >/dev/null 2>&1 || rollback
sleep 3
"$BIN" test-hub --config "$CONFIG" >/tmp/labprobe/install-test.log 2>&1 || rollback
if [ "$0" != "$INSTALL_DIR/labprobe-install.sh" ]; then
  cp "$0" "$INSTALL_DIR/labprobe-install.sh" || rollback
fi
chmod 0755 "$INSTALL_DIR/labprobe-install.sh"
say "安装完成"
"$BIN" status --config "$CONFIG"
say "诊断：labrelay doctor / status / test-hub"
