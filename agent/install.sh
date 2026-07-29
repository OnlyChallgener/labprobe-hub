#!/bin/sh
# LabRelay universal OpenWrt/BusyBox installer.
# Usage:
#   sh install.sh HUB_URL HOOK_TOKEN ROUTER_NAME [LOCAL_BINARY] [REPOSITORY_ROOT]
set -eu

log() { printf '[LabRelay] %s\n' "$*"; }
fail() { printf '[LabRelay] ERROR: %s\n' "$*" >&2; exit 1; }

HUB_URL="${1:-${HUB_URL:-}}"
HOOK_TOKEN="${2:-${HOOK_TOKEN:-}}"
ROUTER_NAME="${3:-${ROUTER_NAME:-$(hostname 2>/dev/null || echo router)}}"
LOCAL_BINARY="${4:-${LABRELAY_BINARY:-}}"
REPOSITORY_ROOT="${5:-${LABRELAY_REPOSITORY_ROOT:-https://lab.net86.dynv6.net:27772}}"
REPOSITORY_ROOT="${REPOSITORY_ROOT%/}"

[ -n "$HUB_URL" ] || fail 'missing HUB_URL (first argument)'
[ -n "$HOOK_TOKEN" ] || fail 'missing HOOK_TOKEN (second argument)'
[ -n "$ROUTER_NAME" ] || ROUTER_NAME=router

case "$(uname -m 2>/dev/null || true)" in
  aarch64|arm64|armv8*) ARCH=arm64 ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) fail "unsupported architecture: $(uname -m 2>/dev/null || echo unknown)" ;;
esac

TMP_DIR="/tmp/labrelay-install.$$"
MANIFEST="$TMP_DIR/latest.json"
DOWNLOADED_BINARY="$TMP_DIR/labrelay"
BACKUP_BINARY="$TMP_DIR/labrelay.backup"
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

http_get() {
  url="$1"; output="$2"
  rm -f "$output"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --connect-timeout 7 --max-time 90 --retry 2 --retry-delay 1 \
      -A 'LabRelay-Installer/2' "$url" -o "$output" >/dev/null 2>&1
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -T 90 -t 2 -O "$output" "$url"
    return $?
  fi
  return 127
}

is_elf() {
  [ -s "$1" ] || return 1
  magic="$(dd if="$1" bs=1 count=4 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')"
  [ "$magic" = '7f454c46' ]
}

json_value() {
  path="$1"; file="$2"
  if command -v jsonfilter >/dev/null 2>&1; then
    jsonfilter -i "$file" -e "$path" 2>/dev/null | head -n 1
    return
  fi
  key="${path##*.}"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | head -n 1
}

try_download_binary() {
  url="$1"
  [ -n "$url" ] || return 1
  log "downloading $url"
  if http_get "$url" "$DOWNLOADED_BINARY" && is_elf "$DOWNLOADED_BINARY"; then
    return 0
  fi
  rm -f "$DOWNLOADED_BINARY"
  return 1
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
  is_elf "$DOWNLOADED_BINARY" || fail "local binary is not an ELF executable: $LOCAL_BINARY"
  log "using local binary $LOCAL_BINARY"
else
  manifest_ok=0
  for manifest_url in \
    "$REPOSITORY_ROOT/agent/latest.json" \
    "$REPOSITORY_ROOT/latest.json" \
    "${HUB_URL%/}/agent/latest.json"; do
    log "fetching manifest $manifest_url"
    if http_get "$manifest_url" "$MANIFEST" && grep -q '"versionName"' "$MANIFEST" 2>/dev/null; then
      manifest_ok=1
      break
    fi
  done

  downloaded=0
  if [ "$manifest_ok" = 1 ]; then
    if [ "$ARCH" = arm64 ]; then
      primary="$(json_value '@.binaries.arm64.url' "$MANIFEST")"
      fallback="$(json_value '@.binaries.arm64.fallbackUrl' "$MANIFEST")"
    else
      primary="$(json_value '@.binaries.amd64.url' "$MANIFEST")"
      fallback="$(json_value '@.binaries.amd64.fallbackUrl' "$MANIFEST")"
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
        "$REPOSITORY_ROOT/agent/$name" \
        "$REPOSITORY_ROOT/$name" \
        "https://github.com/OnlyChallgener/labprobe-hub/releases/latest/download/$name"; do
        if try_download_binary "$url"; then downloaded=1; break 2; fi
      done
    done
  fi
  [ "$downloaded" = 1 ] || fail 'unable to download LabRelay binary; upload the complete agent bundle or repair /agent/latest.json'
fi

chmod 755 "$DOWNLOADED_BINARY"
"$DOWNLOADED_BINARY" version >/dev/null 2>&1 || fail 'downloaded binary cannot run on this router'

mkdir -p /etc/labprobe /usr/bin /etc/init.d /tmp/labrelay
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
  procd_open_instance
  procd_set_param command /usr/bin/labrelay daemon --config /etc/labprobe/relay.json --socket /tmp/labrelay.sock --state /tmp/labrelay/state.json --pid /tmp/labrelay.pid --port-min 20000 --port-max 20020 --lan-if br-lan
  procd_set_param respawn 5 5 0
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_set_param limits nofile=4096 4096
  procd_close_instance
}
EOF

cat > /etc/init.d/labrelay_agent <<'EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=97
STOP=10
start_service() {
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

log "installed $(/usr/bin/labrelay version 2>/dev/null || echo LabRelay)"
log "router=$ROUTER_NAME hub=${HUB_URL%/}"
log 'services: /etc/init.d/labrelay and /etc/init.d/labrelay_agent'
log 'logs: logread | grep -i labrelay; /tmp/labprobe/labrelay-agent.log'
