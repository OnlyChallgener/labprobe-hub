#!/bin/sh
# Usage:
#   sh install_labrelay.sh http://192.168.5.46:58443 HOOK_TOKEN BE72Pro [labrelay_binary]
# The firewall is intentionally NOT modified.
set -eu

HUB_URL="${1:-}"
HOOK_TOKEN="${2:-}"
ROUTER_NAME="${3:-BE72Pro}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY_SOURCE="${4:-$SCRIPT_DIR/labrelay-aarch64-musl}"

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

mkdir -p /etc/labprobe /tmp/labrelay
# Stop the old processes before replacing a running executable.
[ -x /etc/init.d/labrelay_agent ] && /etc/init.d/labrelay_agent stop 2>/dev/null || true
[ -x /etc/init.d/labrelay ] && /etc/init.d/labrelay stop 2>/dev/null || true
rm -f /tmp/labrelay.sock /tmp/labrelay.pid

cp "$BINARY_SOURCE" /usr/bin/labrelay
cp "$SCRIPT_DIR/labrelay_agent.sh" /etc/labprobe/labrelay_agent.sh
cp "$SCRIPT_DIR/labrelay.init" /etc/init.d/labrelay
cp "$SCRIPT_DIR/labrelay-agent.init" /etc/init.d/labrelay_agent
chmod 0755 /usr/bin/labrelay /etc/labprobe/labrelay_agent.sh /etc/init.d/labrelay /etc/init.d/labrelay_agent

cat > /etc/labprobe/relay-agent.conf <<CFG
HUB_URL='$HUB_URL'
HOOK_TOKEN='$HOOK_TOKEN'
ROUTER_NAME='$ROUTER_NAME'
POLL_INTERVAL='5'
STATUS_INTERVAL='10'
CFG
chmod 600 /etc/labprobe/relay-agent.conf

if [ ! -f /etc/labprobe/relay.json ]; then
    cat > /etc/labprobe/relay.json <<'JSON'
{
  "version": 1,
  "rules": []
}
JSON
    chmod 600 /etc/labprobe/relay.json
fi

/etc/init.d/labrelay enable
/etc/init.d/labrelay_agent enable
/etc/init.d/labrelay start
sleep 2
/etc/init.d/labrelay_agent start
sleep 2

echo "[LabRelay] installed"
echo "[LabRelay] firewall unchanged; manually allow IPv6 INPUT TCP 20000-20020"
/usr/bin/labrelay version
/usr/bin/labrelay ctl '{"action":"status"}' 2>/dev/null || true
