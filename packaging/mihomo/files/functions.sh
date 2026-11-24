#!/bin/sh
# Functions shared by procd and the local administration command.
MIHOMO_HOME="${MIHOMO_HOME:-/etc/mihomo}"

mihomo_error() {
    echo "mihomo-web: $*" >&2
    logger -t mihomo-web "$*"
}

mihomo_lan_address() {
    MIHOMO_LAN_ADDRESS="$(uci -q get network.lan.ipaddr 2>/dev/null)"
    MIHOMO_LAN_ADDRESS="${MIHOMO_LAN_ADDRESS%%/*}"
    # No wildcard/loopback/WAN fallback if LAN information is unavailable.
    printf '%s\n' "$MIHOMO_LAN_ADDRESS" | awk '
        BEGIN { FS="."; valid=0 }
        NR == 1 && NF == 4 {
            valid=1
            for (i=1; i<=4; i++) {
                if ($i !~ /^[0-9]+$/ || length($i)>3 || $i+0>255 || (length($i)>1 && substr($i,1,1)=="0")) valid=0
            }
            if ($1+0==0 || $1+0==127 || $1+0>=224) valid=0
        }
        END { exit !(valid && NR == 1) }
    ' || { mihomo_error 'No valid LAN IPv4 address in network.lan.ipaddr; refusing to listen.'; return 1; }
    MIHOMO_CONTROLLER_PORT="$(uci -q get mihomo_web.main.controller_port 2>/dev/null)"
    [ -n "$MIHOMO_CONTROLLER_PORT" ] || MIHOMO_CONTROLLER_PORT=9090
    case "$MIHOMO_CONTROLLER_PORT" in ''|*[!0-9]*) mihomo_error 'Invalid controller port.'; return 1;; esac
    [ "${#MIHOMO_CONTROLLER_PORT}" -le 5 ] &&
        [ "$MIHOMO_CONTROLLER_PORT" -ge 1024 ] && [ "$MIHOMO_CONTROLLER_PORT" -le 65535 ] || {
        mihomo_error 'Controller port must be between 1024 and 65535.'; return 1;
    }
}

mihomo_new_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    elif command -v hexdump >/dev/null 2>&1; then
        hexdump -v -n 32 -e '/1 "%02x"' /dev/urandom
    else
        mihomo_error 'A cryptographic random generator (openssl or hexdump) is required.'
        return 1
    fi
}

mihomo_prepare() {
    mihomo_lan_address || return 1
    umask 077
    mkdir -p "$MIHOMO_HOME" || return 1
    chmod 700 "$MIHOMO_HOME" || return 1
    [ -f "$MIHOMO_HOME/config.yaml" ] || { mihomo_error 'Missing config.yaml.'; return 1; }
    chmod 600 "$MIHOMO_HOME/config.yaml" || return 1
    if [ ! -e "$MIHOMO_HOME/api.secret" ]; then
        MIHOMO_API_SECRET="$(mihomo_new_secret)"
        [ "${#MIHOMO_API_SECRET}" = 64 ] || { mihomo_error 'Unable to generate API secret.'; return 1; }
        (set -C; printf '%s\n' "$MIHOMO_API_SECRET" > "$MIHOMO_HOME/api.secret") || return 1
    fi
    chmod 600 "$MIHOMO_HOME/api.secret" || return 1
    MIHOMO_API_SECRET="$(cat "$MIHOMO_HOME/api.secret")"
    case "$MIHOMO_API_SECRET" in ''|*[!0-9a-f]*) mihomo_error 'Invalid api.secret; refusing to start.'; return 1;; esac
    [ "${#MIHOMO_API_SECRET}" = 64 ] || { mihomo_error 'Invalid api.secret length.'; return 1; }
    if grep -q '@LAN_ADDRESS@' "$MIHOMO_HOME/config.yaml"; then
        sed "s/@LAN_ADDRESS@/$MIHOMO_LAN_ADDRESS/g" "$MIHOMO_HOME/config.yaml" > "$MIHOMO_HOME/.config.bootstrap" || return 1
        chmod 600 "$MIHOMO_HOME/.config.bootstrap" &&
            mv "$MIHOMO_HOME/.config.bootstrap" "$MIHOMO_HOME/config.yaml" || return 1
    fi
}
