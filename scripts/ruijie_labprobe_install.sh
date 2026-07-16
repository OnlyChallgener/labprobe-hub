#!/bin/sh
# LabProbe Ruijie agent installer/upgrader.
# Idempotent: safe to run multiple times.
# Usage:
#   sh ruijie_labprobe_install.sh http://192.168.5.46:58443 YOUR_HOOK_TOKEN [ROUTER_NAME]

HUB_BASE="$1"
HOOK_TOKEN="$2"
ROUTER_NAME_ARG="${3:-BE72Pro}"

INSTALL_DIR="/etc/labprobe"
AGENT_PATH="$INSTALL_DIR/ruijie_push_to_labprobe.sh"
CRON_TMP="/tmp/labprobe_cron_new"
TS="$(date +%Y%m%d%H%M%S)"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)"
SOURCE_AGENT="$SCRIPT_DIR/ruijie_push_to_labprobe.sh"
[ -f "$SOURCE_AGENT" ] || SOURCE_AGENT="./ruijie_push_to_labprobe.sh"
[ -f "$SOURCE_AGENT" ] || SOURCE_AGENT="/tmp/ruijie_push_to_labprobe.sh"

if [ ! -f "$SOURCE_AGENT" ]; then
  echo "[LabProbe] ERROR: cannot find ruijie_push_to_labprobe.sh beside installer"
  exit 1
fi

extract_value() {
  file="$1"
  key="$2"
  [ -f "$file" ] || return
  sed -n "s/^$key=\"\\(.*\\)\"/\\1/p" "$file" | head -n1
}

backup_file() {
  f="$1"
  [ -f "$f" ] || return
  if [ -f "$f.bak" ]; then
    mv "$f" "$f.bak.$TS"
  else
    mv "$f" "$f.bak"
  fi
}

stop_old_processes() {
  ps 2>/dev/null \
    | grep -E '/etc/labprobe/(push_devices|push_router_wan6|watch_devices|ruijie_push_to_labprobe)\.sh' \
    | grep -v grep \
    | awk '{print $1}' \
    | while read pid; do
        [ -z "$pid" ] && continue
        [ "$pid" = "$$" ] && continue
        kill "$pid" 2>/dev/null
      done
}

clean_old_tmp() {
  rm -rf /tmp/labprobe_agent.lock /tmp/labprobe_watch_state
  rm -f /tmp/labprobe_user_list.json /tmp/labprobe_user_list.err
  rm -f /tmp/labprobe_ruijie_user_list.json /tmp/labprobe_ruijie_err.log /tmp/labprobe_ruijie_post.out
  rm -f /tmp/labprobe_snapshot_post.out /tmp/labprobe_devices.log /tmp/labprobe_router_wan6.log
  rm -f /tmp/labprobe_watch_last_resp.log /tmp/labprobe_watch.log
}

install_agent() {
  mkdir -p "$INSTALL_DIR"
  old_hub_url="$(extract_value "$AGENT_PATH" HUB_URL)"
  old_token="$(extract_value "$AGENT_PATH" LABPROBE_TOKEN)"
  old_router_name="$(extract_value "$AGENT_PATH" ROUTER_NAME)"

  if [ "$SOURCE_AGENT" != "$AGENT_PATH" ] && [ -f "$AGENT_PATH" ]; then
    backup_file "$AGENT_PATH"
  fi
  if [ "$SOURCE_AGENT" != "$AGENT_PATH" ]; then
    cp "$SOURCE_AGENT" "$AGENT_PATH"
  fi
  chmod +x "$AGENT_PATH"

  [ -z "$HUB_BASE" ] && HUB_BASE="${old_hub_url%%/hook/*}"
  [ -z "$HOOK_TOKEN" ] && HOOK_TOKEN="$old_token"
  [ -z "$ROUTER_NAME_ARG" ] && ROUTER_NAME_ARG="$old_router_name"
  [ -z "$ROUTER_NAME_ARG" ] && ROUTER_NAME_ARG="BE72Pro"

  if [ -n "$HUB_BASE" ] && [ -n "$HOOK_TOKEN" ]; then
    new_url="$HUB_BASE/hook/ruijie/devices?token=$HOOK_TOKEN"
    sed -i \
      -e "s#^HUB_URL=.*#HUB_URL=\"$new_url\"#" \
      -e "s#^LABPROBE_TOKEN=.*#LABPROBE_TOKEN=\"$HOOK_TOKEN\"#" \
      -e "s#^ROUTER_NAME=.*#ROUTER_NAME=\"$ROUTER_NAME_ARG\"#" \
      "$AGENT_PATH"
  else
    echo "[LabProbe] WARN: HUB_BASE or HOOK_TOKEN empty; kept script defaults, please edit $AGENT_PATH"
  fi
}

disable_old_scripts() {
  backup_file "$INSTALL_DIR/push_devices.sh"
  backup_file "$INSTALL_DIR/push_router_wan6.sh"
  backup_file "$INSTALL_DIR/watch_devices.sh"
}

install_cron() {
  crontab -l > /tmp/labprobe_cron_old 2>/dev/null
  grep -v '/etc/labprobe/push_devices.sh' /tmp/labprobe_cron_old \
    | grep -v '/etc/labprobe/push_router_wan6.sh' \
    | grep -v '/etc/labprobe/watch_devices.sh' \
    | grep -v '/etc/labprobe/ruijie_push_to_labprobe.sh' \
    > "$CRON_TMP"
  echo "*/1 * * * * /etc/labprobe/ruijie_push_to_labprobe.sh >/tmp/labprobe_agent_cron.out 2>&1" >> "$CRON_TMP"
  crontab "$CRON_TMP"
  /etc/init.d/cron enable >/dev/null 2>&1
  /etc/init.d/cron restart >/dev/null 2>&1
}

clean_rc_local() {
  [ -f /etc/rc.local ] || return
  cp /etc/rc.local "/tmp/rc.local.labprobe.$TS"
  sed -i \
    -e '/\/etc\/labprobe\/watch_devices.sh/d' \
    -e '/\/etc\/labprobe\/push_devices.sh/d' \
    -e '/\/etc\/labprobe\/push_router_wan6.sh/d' \
    -e '/\/etc\/labprobe\/ruijie_push_to_labprobe.sh/d' \
    /etc/rc.local
}

print_final_state() {
  echo
  echo "[LabProbe] final scripts:"
  ls -l "$INSTALL_DIR" 2>/dev/null | grep -E 'ruijie_push_to_labprobe|push_devices|push_router_wan6|watch_devices' || true
  echo
  echo "[LabProbe] final cron:"
  crontab -l 2>/dev/null | grep labprobe || true
  echo
  echo "[LabProbe] final rc.local LabProbe entries:"
  grep labprobe /etc/rc.local 2>/dev/null || echo "(none)"
  echo
  echo "[LabProbe] current LabProbe processes:"
  ps 2>/dev/null | grep labprobe | grep -v grep || echo "(none)"
}

stop_old_processes
disable_old_scripts
install_agent
clean_old_tmp
clean_rc_local
install_cron

"$AGENT_PATH"
print_final_state
