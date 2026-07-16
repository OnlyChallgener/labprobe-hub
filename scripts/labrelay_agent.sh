#!/bin/sh
# LabProbe PortMap router agent. Only exchanges structured JSON with Hub.
# It never edits firewall rules and never executes arbitrary commands from Hub.

CONF="${LABRELAY_AGENT_CONF:-/etc/labprobe/relay-agent.conf}"
BIN="${LABRELAY_BIN:-/usr/bin/labrelay}"
SOCKET="${LABRELAY_SOCKET:-/tmp/labrelay.sock}"
TMP_DIR="/tmp/labrelay-agent"
LOG="/tmp/labrelay-agent.log"

[ -r "$CONF" ] && . "$CONF"
HUB_URL="${HUB_URL%/}"
ROUTER_NAME="${ROUTER_NAME:-BE72Pro}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
STATUS_INTERVAL="${STATUS_INTERVAL:-10}"
CURL="$(command -v curl 2>/dev/null)"

log_error() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"
    [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null)" -gt 131072 ] && {
        tail -c 65536 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
    }
}

validate_config() {
    [ -x "$BIN" ] || { log_error "labrelay binary not executable: $BIN"; return 1; }
    [ -n "$CURL" ] || { log_error "curl not found"; return 1; }
    [ -n "$HUB_URL" ] || { log_error "HUB_URL is empty"; return 1; }
    [ -n "$HOOK_TOKEN" ] || { log_error "HOOK_TOKEN is empty"; return 1; }
    return 0
}

fetch_commands() {
    "$CURL" -fsS --connect-timeout 3 --max-time 8 \
        -H "X-LabProbe-Token: $HOOK_TOKEN" \
        "$HUB_URL/api/router/portmaps/commands?router=$ROUTER_NAME&limit=20" \
        -o "$TMP_DIR/commands.json"
}

apply_commands() {
    "$BIN" agent-apply --socket "$SOCKET" --file "$TMP_DIR/commands.json" \
        > "$TMP_DIR/acks.json" 2> "$TMP_DIR/apply.err" || {
        log_error "apply commands failed: $(tail -c 300 "$TMP_DIR/apply.err" 2>/dev/null)"
        return 1
    }
    "$CURL" -fsS --connect-timeout 3 --max-time 8 \
        -H "X-LabProbe-Token: $HOOK_TOKEN" \
        -H "Content-Type: application/json" \
        --data-binary @"$TMP_DIR/acks.json" \
        "$HUB_URL/api/router/portmaps/ack?router=$ROUTER_NAME" \
        -o "$TMP_DIR/ack-response.json" || log_error "ack upload failed"
}

push_status() {
    "$BIN" ctl --socket "$SOCKET" '{"action":"status"}' \
        > "$TMP_DIR/status.json" 2> "$TMP_DIR/status.err" || {
        log_error "read relay status failed: $(tail -c 300 "$TMP_DIR/status.err" 2>/dev/null)"
        return 1
    }
    "$CURL" -fsS --connect-timeout 3 --max-time 8 \
        -H "X-LabProbe-Token: $HOOK_TOKEN" \
        -H "Content-Type: application/json" \
        --data-binary @"$TMP_DIR/status.json" \
        "$HUB_URL/api/router/portmaps/status?router=$ROUTER_NAME" \
        -o "$TMP_DIR/status-response.json" || log_error "status upload failed"
}

run_once() {
    mkdir -p "$TMP_DIR"
    validate_config || return 1
    if fetch_commands; then
        apply_commands
    fi
    push_status
}

daemon_loop() {
    mkdir -p "$TMP_DIR"
    validate_config || exit 1
    last_status=0
    while :; do
        now="$(date +%s)"
        if fetch_commands; then
            apply_commands
        fi
        if [ $((now - last_status)) -ge "$STATUS_INTERVAL" ]; then
            push_status
            last_status="$now"
        fi
        sleep "$POLL_INTERVAL"
    done
}

case "${1:-daemon}" in
    once) run_once ;;
    daemon) daemon_loop ;;
    *) echo "Usage: $0 [daemon|once]" >&2; exit 2 ;;
esac
