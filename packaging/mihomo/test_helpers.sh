#!/bin/sh
# Run on Linux: sh test_helpers.sh. No service, route or system configuration changes.
set -eu
TEST_PACKAGE_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
TEST_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mihomo-helper-test.XXXXXX")"
trap 'rm -rf "$TEST_WORK_DIR"' EXIT HUP INT TERM
mkdir -p "$TEST_WORK_DIR/bin" "$TEST_WORK_DIR/home"
cat > "$TEST_WORK_DIR/bin/uci" <<'EOF'
#!/bin/sh
case "$*" in
    '-q get network.lan.ipaddr') printf '%s\n' "${TEST_LAN:-}";;
    '-q get mihomo_web.main.controller_port') printf '%s\n' "${TEST_PORT:-9090}";;
    *) exit 1;;
esac
EOF
cat > "$TEST_WORK_DIR/bin/logger" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 755 "$TEST_WORK_DIR/bin/uci" "$TEST_WORK_DIR/bin/logger"
export PATH="$TEST_WORK_DIR/bin:$PATH"
export MIHOMO_HOME="$TEST_WORK_DIR/home" TEST_LAN='192.168.110.1/24' TEST_PORT=9090
cp "$TEST_PACKAGE_DIR/files/config.yaml" "$MIHOMO_HOME/config.yaml"
. "$TEST_PACKAGE_DIR/files/functions.sh"

mihomo_prepare
[ "$MIHOMO_LAN_ADDRESS" = '192.168.110.1' ]
[ "${#MIHOMO_API_SECRET}" = 64 ]
[ "$(stat -c %a "$MIHOMO_HOME")" = 700 ]
[ "$(stat -c %a "$MIHOMO_HOME/api.secret")" = 600 ]
[ "$(stat -c %a "$MIHOMO_HOME/config.yaml")" = 600 ]
grep -q 'bind-address: "192.168.110.1"' "$MIHOMO_HOME/config.yaml"
TEST_INITIAL_SECRET="$MIHOMO_API_SECRET"
mihomo_prepare
[ "$MIHOMO_API_SECRET" = "$TEST_INITIAL_SECRET" ]
echo 'PASS: LAN bind bootstrap, cryptographic secret, file permissions and restart persistence'

for TEST_LAN in '' '*' '0.0.0.0' '127.0.0.1' '224.0.0.1' '300.1.1.1' '192.168.001.1' '192.168.1.1
0.0.0.0'; do
    export TEST_LAN
    if mihomo_prepare >/dev/null 2>&1; then
        echo "FAIL: invalid LAN accepted" >&2
        exit 1
    fi
done
[ "$(cat "$MIHOMO_HOME/api.secret")" = "$TEST_INITIAL_SECRET" ]
echo 'PASS: missing, wildcard, loopback, multicast, invalid and multiline LAN values fail closed'

TEST_LAN='192.168.5.1'
export TEST_LAN
for TEST_PORT in 0 80 65536 abc '9090;id' 9999999999999999999999999; do
    export TEST_PORT
    if mihomo_prepare >/dev/null 2>&1; then
        echo 'FAIL: invalid management port accepted' >&2
        exit 1
    fi
done
TEST_PORT=9091
export TEST_PORT
mihomo_prepare
[ "$MIHOMO_CONTROLLER_PORT" = 9091 ]
[ "$MIHOMO_LAN_ADDRESS" = '192.168.5.1' ]
grep -q 'bind-address: "192.168.110.1"' "$MIHOMO_HOME/config.yaml"
[ "$MIHOMO_API_SECRET" = "$TEST_INITIAL_SECRET" ]
echo 'PASS: valid port and LAN changes update controller without overwriting existing user configuration'

MIHOMO_HOME="$TEST_WORK_DIR/second-home"
export MIHOMO_HOME
mkdir -p "$MIHOMO_HOME"
cp "$TEST_PACKAGE_DIR/files/config.yaml" "$MIHOMO_HOME/config.yaml"
mihomo_prepare
[ "$MIHOMO_API_SECRET" != "$TEST_INITIAL_SECRET" ]
printf 'not-a-valid-secret\n' > "$MIHOMO_HOME/api.secret"
if mihomo_prepare >/dev/null 2>&1; then
    echo 'FAIL: invalid existing secret accepted' >&2
    exit 1
fi
[ "$(cat "$MIHOMO_HOME/api.secret")" = 'not-a-valid-secret' ]
echo 'PASS: independent installations get different secrets; damaged secrets fail closed without replacement'

for TEST_SCRIPT in "$TEST_PACKAGE_DIR/files/mihomo-wrapper" "$TEST_PACKAGE_DIR/files/mihomo-web" "$TEST_PACKAGE_DIR/files/mihomo-web.init" \
    "$TEST_PACKAGE_DIR/files/functions.sh" "$TEST_PACKAGE_DIR/files/preinst" \
    "$TEST_PACKAGE_DIR/files/postinst" "$TEST_PACKAGE_DIR/files/prerm"; do
    sh -n "$TEST_SCRIPT"
done
echo 'PASS: POSIX shell syntax for every installed executable/helper'
