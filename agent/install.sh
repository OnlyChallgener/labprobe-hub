#!/bin/sh
# LabRelay universal OpenWrt/BusyBox installer.
# First install:
#   sh install.sh HUB_URL HOOK_TOKEN ROUTER_NAME [LOCAL_BINARY] [REPOSITORY_ROOT]
# Upgrade with an existing /etc/labprobe/agent.json:
#   sh install.sh
#   sh install.sh upgrade
set -eu

log() { printf '[LabRelay] %s\n' "$*"; }
fail() { printf '[LabRelay] ERROR: %s\n' "$*" >&2; exit 1; }

config_value() {
  path="$1"; key="$2"; file="$3"
  [ -f "$file" ] || return 0
  if command -v jsonfilter >/dev/null 2>&1; then
    jsonfilter -i "$file" -e "$path" 2>/dev/null | head -n 1
  else
    sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | head -n 1
  fi
}

EXISTING_CONFIG=/etc/labprobe/agent.json
SAVED_HUB="$(config_value '@.hubUrl' hubUrl "$EXISTING_CONFIG")"
SAVED_TOKEN="$(config_value '@.hookToken' hookToken "$EXISTING_CONFIG")"
SAVED_NAME="$(config_value '@.routerName' routerName "$EXISTING_CONFIG")"

# APP-driven upgrades invoke the downloaded installer as `sh install.sh upgrade`.
# Treat that as an action, never as the Hub URL. Older bundles accidentally
# wrote `hubUrl: "upgrade"`, which left the new binary unable to report back.
case "${1:-}" in
  install|upgrade|repair)
    ACTION="$1"
    shift
    ;;
  *) ACTION="install" ;;
esac

HUB_URL="${1:-${HUB_URL:-$SAVED_HUB}}"
HOOK_TOKEN="${2:-${HOOK_TOKEN:-$SAVED_TOKEN}}"
ROUTER_NAME="${3:-${ROUTER_NAME:-$SAVED_NAME}}"
[ -n "$ROUTER_NAME" ] || ROUTER_NAME="$(hostname 2>/dev/null || echo router)"
LOCAL_BINARY="${4:-${LABRELAY_BINARY:-}}"
REPOSITORY_ROOT="${5:-${LABRELAY_REPOSITORY_ROOT:-${LABPROBE_UPDATE_ROOT:-${HUB_URL:-https://lab.net86.dynv6.net:27772}}}}"
REPOSITORY_ROOT="${REPOSITORY_ROOT%/}"
PUBLIC_FALLBACK_ROOT="${LABRELAY_PUBLIC_ROOT:-https://lab.net86.dynv6.net:27772}"
PUBLIC_FALLBACK_ROOT="${PUBLIC_FALLBACK_ROOT%/}"

[ -n "$HUB_URL" ] || fail 'missing HUB_URL and no existing /etc/labprobe/agent.json'
[ -n "$HOOK_TOKEN" ] || fail 'missing HOOK_TOKEN and no existing /etc/labprobe/agent.json'
case "$HUB_URL" in
  http://*|https://*) ;;
  *) fail "invalid HUB_URL: $HUB_URL" ;;
esac

case "$(uname -m 2>/dev/null || true)" in
  aarch64|arm64|armv8*) ARCH=arm64 ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) fail "unsupported architecture: $(uname -m 2>/dev/null || echo unknown)" ;;
esac

TMP_DIR="/tmp/labrelay-install.$$"
MANIFEST="$TMP_DIR/latest.json"
DOWNLOADED_BINARY="$TMP_DIR/labrelay"
DOWNLOADED_URL=""
BACKUP_BINARY="$TMP_DIR/labrelay.backup"
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

http_get() {
  url="$1"; output="$2"
  rm -f "$output"
  if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
  else
    if command -v wget >/dev/null 2>&1; then
      DOWNLOADER="wget"
    else
      fail "缺少 curl 或 wget，无法下载安装包"
    fi
  fi
  if [ "$DOWNLOADER" = "curl" ]; then
    curl -fL --connect-timeout 7 --max-time 90 --retry 2 --retry-delay 1 \
      -A 'LabRelay-Installer/4' "$url" -o "$output" >/dev/null 2>&1
    return $?
  else
    wget -q -T 90 -t 2 -O "$output" "$url"
    return $?
  fi
}

# Do not depend on od/hexdump/file: some vendor OpenWrt builds omit all of them.
# A valid LabRelay binary must be executable on this router and answer the version command.
is_labrelay_binary() {
  [ -s "$1" ] || return 1
  chmod 755 "$1" 2>/dev/null || return 1
  "$1" version >/dev/null 2>&1
}

json_value() {
  path="$1"; key="$2"; file="$3"
  if command -v jsonfilter >/dev/null 2>&1; then
    jsonfilter -i "$file" -e "$path" 2>/dev/null | head -n 1
  else
    sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | head -n 1
  fi
}

try_download_binary() {
  url="$1"
  [ -n "$url" ] || return 1
  log "downloading $url"
  if http_get "$url" "$DOWNLOADED_BINARY" && is_labrelay_binary "$DOWNLOADED_BINARY"; then
    DOWNLOADED_URL="$url"
    return 0
  fi
  rm -f "$DOWNLOADED_BINARY"
  return 1
}

# Verify the downloaded binary against the bundle checksums when they are
# reachable. Missing checksums degrade to the historic verify-by-run behavior;
# a mismatch aborts before anything is installed.
verify_downloaded_binary() {
  [ -n "$DOWNLOADED_URL" ] || return 0
  if [ "${LABRELAY_SKIP_CHECKSUM:-0}" = "1" ]; then
    log 'LABRELAY_SKIP_CHECKSUM=1 set; skipping sha256 verification'
    return 0
  fi
  sums="$TMP_DIR/checksums.txt"
  name="$(basename "$DOWNLOADED_URL")"
  fetched=0
  for sums_url in \
    "${DOWNLOADED_URL%/*}/checksums.txt" \
    "${HUB_URL%/}/agent/checksums.txt" \
    "$REPOSITORY_ROOT/agent/checksums.txt" \
    "$PUBLIC_FALLBACK_ROOT/agent/checksums.txt"; do
    if http_get "$sums_url" "$sums" && [ -s "$sums" ]; then
      fetched=1
      break
    fi
  done
  [ "$fetched" = 1 ] || { log 'checksums.txt unavailable; continuing without verification'; return 0; }
  command -v sha256sum >/dev/null 2>&1 || fail '缺少 sha256sum，无法校验下载的二进制；可设置 LABRELAY_SKIP_CHECKSUM=1 跳过'
  expected="$(grep -E "^[0-9a-fA-F]{64}[[:space:]]+\*?${name}([[:space:]]|\$)" "$sums" | head -n 1 | awk '{print $1}')"
  if [ -z "$expected" ]; then
    log "checksums.txt has no entry for $name; continuing without verification"
    return 0
  fi
  actual="$(sha256sum "$DOWNLOADED_BINARY" | awk '{print $1}')"
  [ -n "$expected" ] && [ "$actual" = "$expected" ] || fail "下载的二进制 sha256 校验失败（$actual != $expected）；未安装任何文件"
  log "sha256 verified: $actual"
}

# Prefer a bundle-local binary. This keeps installation working even if the update server is unavailable.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo /tmp)"
if [ -z "$LOCAL_BINARY" ]; then
  for candidate in \
    "$SCRIPT_DIR/labrelay-linux-$ARCH" \
    "$SCRIPT_DIR/labrelay-$ARCH-musl" \
    "$SCRIPT_DIR/labrelay-aarch64-musl" \
    "/tmp/labrelay-linux-$ARCH" \
    "/tmp/labrelay-aarch64-musl"; do
    if [ -f "$candidate" ]; then LOCAL_BINARY="$candidate"; break; fi
  done
fi

if [ -n "$LOCAL_BINARY" ]; then
  [ -f "$LOCAL_BINARY" ] || fail "local binary not found: $LOCAL_BINARY"
  cp "$LOCAL_BINARY" "$DOWNLOADED_BINARY"
  is_labrelay_binary "$DOWNLOADED_BINARY" || fail "local LabRelay binary cannot run on this router: $LOCAL_BINARY"
  log "using local binary $LOCAL_BINARY"
else
  manifest_ok=0
  for manifest_url in \
    "${HUB_URL%/}/agent/latest.json" \
    "$REPOSITORY_ROOT/agent/latest.json" \
    "$REPOSITORY_ROOT/latest.json" \
    "$PUBLIC_FALLBACK_ROOT/agent/latest.json"; do
    log "fetching manifest $manifest_url"
    if http_get "$manifest_url" "$MANIFEST" && grep -q '"versionName"' "$MANIFEST" 2>/dev/null; then
      manifest_ok=1
      break
    fi
  done

  downloaded=0
  if [ "$manifest_ok" = 1 ]; then
    if [ "$ARCH" = arm64 ]; then
      primary="$(json_value '@.binaries.arm64.url' url "$MANIFEST")"
      fallback="$(json_value '@.binaries.arm64.fallbackUrl' fallbackUrl "$MANIFEST")"
    else
      primary="$(json_value '@.binaries.amd64.url' url "$MANIFEST")"
      fallback="$(json_value '@.binaries.amd64.fallbackUrl' fallbackUrl "$MANIFEST")"
    fi
    for url in "$primary" "$fallback"; do
      if try_download_binary "$url"; then downloaded=1; break; fi
    done
  else
    log 'manifest unavailable; trying direct asset fallbacks'
  fi

  if [ "$downloaded" = 0 ]; then
    if [ "$ARCH" = arm64 ]; then
      names='labrelay-linux-arm64 labrelay-aarch64-musl labrelay-linux-aarch64'
    else
      names='labrelay-linux-amd64 labrelay-x86_64-musl labrelay-linux-x86_64'
    fi
    for name in $names; do
      for url in \
        "${HUB_URL%/}/agent/$name" \
        "$REPOSITORY_ROOT/agent/$name" \
        "$REPOSITORY_ROOT/$name" \
        "$PUBLIC_FALLBACK_ROOT/agent/$name" \
        "https://github.com/OnlyChallgener/labprobe-hub/releases/latest/download/$name"; do
        if try_download_binary "$url"; then downloaded=1; break 2; fi
      done
    done
  fi
  [ "$downloaded" = 1 ] || fail 'unable to download a runnable LabRelay binary; upload the complete agent bundle or repair /agent/latest.json'
fi

verify_downloaded_binary
chmod 755 "$DOWNLOADED_BINARY"
"$DOWNLOADED_BINARY" version >/dev/null 2>&1 || fail 'downloaded LabRelay binary cannot run on this router'

mkdir -p /etc/labprobe /usr/bin /etc/init.d /tmp/labrelay /tmp/labprobe
[ -f /etc/labprobe/relay.json ] || printf '%s\n' '{"version":1,"rules":[]}' > /etc/labprobe/relay.json
chmod 600 /etc/labprobe/relay.json

# Stop old services before replacing the running executable.
/etc/init.d/labrelay_agent stop >/dev/null 2>&1 || true
/etc/init.d/labrelay stop >/dev/null 2>&1 || true
killall labrelay >/dev/null 2>&1 || true
sleep 1

if [ -f /usr/bin/labrelay ]; then cp /usr/bin/labrelay "$BACKUP_BINARY"; fi
cp "$DOWNLOADED_BINARY" /usr/bin/labrelay
chmod 755 /usr/bin/labrelay

cat > /etc/init.d/labrelay <<'EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=97
STOP=10
start_service() {
  mkdir -p /tmp/labrelay
  procd_open_instance
  # Some vendor procd builds keep the inherited hard nofile ceiling even when
  # procd_set_param limits requests a higher value. Raise it in a root shell
  # immediately before exec so the Relay daemon really inherits 131072.
  # Relay accepts the union of the two Hub-owned pools:
  # PortMap/IPv6 20000-29999 and STUN local channels 30000-32767.
  procd_set_param command /bin/sh -c 'ulimit -n 131072; exec /usr/bin/labrelay daemon --config /etc/labprobe/relay.json --socket /tmp/labrelay.sock --state /tmp/labrelay/state.json --pid /tmp/labrelay.pid --port-min 20000 --port-max 32767 --lan-if br-lan'
  procd_set_param respawn 5 5 0
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_set_param limits nofile="131072 131072"
  procd_close_instance
}
EOF

cat > /etc/init.d/labrelay_agent <<'EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=98
STOP=10
start_service() {
  mkdir -p /tmp/labprobe
  procd_open_instance
  procd_set_param command /usr/bin/labrelay agent --config /etc/labprobe/agent.json
  procd_set_param respawn 5 5 0
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOF
chmod 755 /etc/init.d/labrelay /etc/init.d/labrelay_agent

if ! /usr/bin/labrelay configure --hub "${HUB_URL%/}" --hook-token "$HOOK_TOKEN" --name "$ROUTER_NAME" --config /etc/labprobe/agent.json; then
  [ -f "$BACKUP_BINARY" ] && cp "$BACKUP_BINARY" /usr/bin/labrelay
  fail 'unable to save Agent configuration; previous binary restored'
fi
chmod 600 /etc/labprobe/agent.json

/etc/init.d/labrelay enable
/etc/init.d/labrelay_agent enable
/etc/init.d/labrelay start
sleep 1
/etc/init.d/labrelay_agent start
sleep 2

if ! /usr/bin/labrelay ctl '{"action":"status"}' >/tmp/labrelay-install-status.json 2>/dev/null; then
  log 'daemon status is not ready yet; procd will continue retrying'
fi

relay_pid=""
for p in $(pidof labrelay 2>/dev/null || true); do
  [ -r "/proc/$p/cmdline" ] || continue
  cmdline="$(tr '\000' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)"
  case "$cmdline" in
    *"/labrelay daemon "*|*" labrelay daemon "*) relay_pid="$p"; break ;;
  esac
done
if [ -n "$relay_pid" ] && [ -r "/proc/$relay_pid/limits" ]; then
  soft="$(awk '/Max open files/ {print $4; exit}' "/proc/$relay_pid/limits" 2>/dev/null || true)"
  hard="$(awk '/Max open files/ {print $5; exit}' "/proc/$relay_pid/limits" 2>/dev/null || true)"
  log "Relay FD limit: soft=${soft:-unknown} hard=${hard:-unknown}"
  case "${soft:-}:${hard:-}" in
    *[!0-9:]*|:*) fail 'unable to verify Relay FD limit' ;;
  esac
  [ "$soft" -ge 65536 ] && [ "$hard" -ge 65536 ] || fail "Relay FD limit did not take effect: soft=$soft hard=$hard"
else
  fail 'Relay daemon is not running; unable to verify FD limit'
fi

log "installed $(/usr/bin/labrelay version 2>/dev/null || echo LabRelay)"
log "router=$ROUTER_NAME hub=${HUB_URL%/}"
log 'services: /etc/init.d/labrelay and /etc/init.d/labrelay_agent'
log 'logs: logread | grep -i labrelay; /tmp/labprobe/labrelay-agent.log'