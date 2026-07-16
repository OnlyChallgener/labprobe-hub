#!/bin/sh
# Install/upgrade LabRelay v0.1.1 and Agent v0.1.1 on OpenWrt.
# Usage:
#   sh install_labrelay.sh http://192.168.5.46:58443 HOOK_TOKEN BE72Pro [labrelay_binary]
# The firewall is intentionally NOT modified.
set -eu

HUB_URL="${1:-}"
HOOK_TOKEN="${2:-}"
ROUTER_NAME="${3:-BE72Pro}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY_SOURCE="${4:-$SCRIPT_DIR/labrelay-aarch64-musl}"
BIN=/usr/bin/labrelay
BIN_NEW=/usr/bin/labrelay.new
BIN_BAK=/usr/bin/labrelay.rollback

[ -n "$HUB_URL" ] || { echo "Missing Hub URL" >&2; exit 2; }
[ -n "$HOOK_TOKEN" ] || { echo "Missing HOOK_TOKEN" >&2; exit 2; }
[ -f "$BINARY_SOURCE" ] || { echo "Binary not found: $BINARY_SOURCE" >&2; exit 2; }

ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|arm64) ;;
    *) echo "Unsupported architecture: $ARCH (expected aarch64)" >&2; exit 2 ;;
esac

command -v ip >/dev/null 2>&1 || { echo "Missing dependency: ip" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "Missing dependency: curl" >&2; exit 2; }
[ -r /etc/rc.common ] || { echo "OpenWrt rc.common not found" >&2; exit 2; }

mkdir -p /etc/labprobe /tmp/labrelay /tmp/labrelay-agent
cp "$BINARY_SOURCE" "$BIN_NEW"
chmod 0755 "$BIN_NEW"
"$BIN_NEW" version >/tmp/labrelay-new-version.txt 2>&1 || {
    cat /tmp/labrelay-new-version.txt >&2
    rm -f "$BIN_NEW"
    echo "New binary validation failed" >&2
    exit 1
}

OLD_PRESENT=0
INSTALL_OK=0
if [ -x "$BIN" ]; then
    OLD_PRESENT=1
    cp "$BIN" "$BIN_BAK"
    chmod 0755 "$BIN_BAK"
fi

rollback() {
    trap - EXIT HUP INT TERM
    echo "[LabRelay] upgrade failed, rolling back" >&2
    [ -x /etc/init.d/labrelay_agent ] && /etc/init.d/labrelay_agent stop 2>/dev/null || true
    [ -x /etc/init.d/labrelay ] && /etc/init.d/labrelay stop 2>/dev/null || true
    if [ "$OLD_PRESENT" -eq 1 ] && [ -x "$BIN_BAK" ]; then
        mv -f "$BIN_BAK" "$BIN"
        /etc/init.d/labrelay start 2>/dev/null || true
        sleep 2
        /etc/init.d/labrelay_agent start 2>/dev/null || true
    fi
    rm -f "$BIN_NEW"
    exit 1
}
trap 'rc=$?; if [ "$INSTALL_OK" -ne 1 ] && [ "$rc" -ne 0 ]; then rollback; fi' EXIT
trap rollback HUP INT TERM

[ -x /etc/init.d/labrelay_agent ] && /etc/init.d/labrelay_agent stop 2>/dev/null || true
[ -x /etc/init.d/labrelay ] && /etc/init.d/labrelay stop 2>/dev/null || true
rm -f /tmp/labrelay.sock /tmp/labrelay.pid
mv -f "$BIN_NEW" "$BIN"

cp "$SCRIPT_DIR/labrelay_agent.sh" /etc/labprobe/labrelay_agent.sh
cp "$SCRIPT_DIR/labrelay.init" /etc/init.d/labrelay
cp "$SCRIPT_DIR/labrelay-agent.init" /etc/init.d/labrelay_agent
chmod 0755 "$BIN" /etc/labprobe/labrelay_agent.sh /etc/init.d/labrelay /etc/init.d/labrelay_agent

cat > /etc/labprobe/relay-agent.conf <<CFG
HUB_URL='$HUB_URL'
HOOK_TOKEN='$HOOK_TOKEN'
ROUTER_NAME='$ROUTER_NAME'
POLL_INTERVAL='5'
STATUS_INTERVAL='10'
AUTH_BACKOFF_SEC='60'
CFG
chmod 600 /etc/labprobe/relay-agent.conf

if [ ! -f /etc/labprobe/labrelay.conf ]; then
    cat > /etc/labprobe/labrelay.conf <<'CFG'
PORT_MIN='20000'
PORT_MAX='20020'
LAN_IF='br-lan'
CFG
    chmod 600 /etc/labprobe/labrelay.conf
fi

if [ ! -f /etc/labprobe/relay.json ]; then
    cat > /etc/labprobe/relay.json <<'JSON'
{
  "version": 2,
  "rules": []
}
JSON
    chmod 600 /etc/labprobe/relay.json
fi

/etc/init.d/labrelay enable
/etc/init.d/labrelay_agent enable
/etc/init.d/labrelay start || rollback
sleep 3
[ -S /tmp/labrelay.sock ] || rollback
"$BIN" ctl '{"action":"status"}' >/tmp/labrelay-install-status.json 2>/tmp/labrelay-install-status.err || rollback
/etc/init.d/labrelay_agent start || rollback
sleep 2

INSTALL_OK=1
trap - EXIT HUP INT TERM
rm -f "$BIN_BAK" "$BIN_NEW"

echo "[LabRelay] installed/upgraded successfully"
"$BIN" version
/etc/labprobe/labrelay_agent.sh version
/etc/labprobe/labrelay_agent.sh test || true
echo "[LabRelay] firewall unchanged; manually allow IPv6 INPUT TCP for configured PORT_MIN-PORT_MAX"
