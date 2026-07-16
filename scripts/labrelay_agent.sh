#!/bin/sh
# LabProbe PortMap router agent v0.1.1 (protocol v2).
# Only exchanges structured JSON with Hub. Never edits firewall rules and never
# executes arbitrary commands received from Hub.

AGENT_VERSION="0.1.1"
PROTOCOL_VERSION="2"
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
AUTH_BACKOFF_SEC="${AUTH_BACKOFF_SEC:-60}"
CURL="$(command -v curl 2>/dev/null)"

log_error() {
    mkdir -p "$TMP_DIR"
    now="$(date +%s)"
    message="$*"
    last_message="$(cat "$TMP_DIR/last-error-message" 2>/dev/null || true)"
    last_epoch="$(cat "$TMP_DIR/last-error-epoch" 2>/dev/null || echo 0)"
    case "$last_epoch" in ''|*[!0-9]*) last_epoch=0 ;; esac
    if [ "$message" = "$last_message" ] && [ $((now - last_epoch)) -lt 60 ]; then
        return 0
    fi
    printf '%s' "$message" > "$TMP_DIR/last-error-message"
    printf '%s' "$now" > "$TMP_DIR/last-error-epoch"
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$message" >> "$LOG"
    [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null)" -gt 131072 ] && {
        tail -c 65536 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
    }
}

clear_last_error() {
    rm -f "$TMP_DIR/last-error-message" "$TMP_DIR/last-error-epoch"
}

validate_config() {
    [ -x "$BIN" ] || { log_error "BINARY_MISSING: labrelay not executable: $BIN"; return 1; }
    [ -n "$CURL" ] || { log_error "DEPENDENCY_MISSING: curl not found"; return 1; }
    [ -n "$HUB_URL" ] || { log_error "CONFIG_ERROR: HUB_URL is empty"; return 1; }
    [ -n "$HOOK_TOKEN" ] || { log_error "CONFIG_ERROR: HOOK_TOKEN is empty"; return 1; }
    return 0
}

common_headers() {
    printf '%s\n' \
        "X-LabProbe-Token: $HOOK_TOKEN" \
        "X-LabProbe-Agent-Version: $AGENT_VERSION" \
        "X-LabProbe-Protocol-Version: $PROTOCOL_VERSION"
}

http_get() {
    output="$1"
    url="$2"
    code="$($CURL -sS --connect-timeout 3 --max-time 8 \
        -H "X-LabProbe-Token: $HOOK_TOKEN" \
        -H "X-LabProbe-Agent-Version: $AGENT_VERSION" \
        -H "X-LabProbe-Protocol-Version: $PROTOCOL_VERSION" \
        -o "$output" -w '%{http_code}' "$url" 2>"$TMP_DIR/curl.err")" || {
        log_error "HUB_UNREACHABLE: $(tail -c 240 "$TMP_DIR/curl.err" 2>/dev/null)"
        return 1
    }
    case "$code" in
        200) clear_last_error; return 0 ;;
        401|403)
            log_error "BAD_HOOK_TOKEN: Hub HTTP $code ($(tail -c 240 "$output" 2>/dev/null))"
            return 2
            ;;
        404)
            log_error "HUB_API_MISSING: Hub HTTP 404; update Hub to v0.8.4+"
            return 1
            ;;
        *)
            log_error "HUB_HTTP_ERROR: HTTP $code ($(tail -c 240 "$output" 2>/dev/null))"
            return 1
            ;;
    esac
}

http_post_file() {
    input="$1"
    output="$2"
    url="$3"
    code="$($CURL -sS --connect-timeout 3 --max-time 8 \
        -H "X-LabProbe-Token: $HOOK_TOKEN" \
        -H "X-LabProbe-Agent-Version: $AGENT_VERSION" \
        -H "X-LabProbe-Protocol-Version: $PROTOCOL_VERSION" \
        -H "Content-Type: application/json" \
        --data-binary @"$input" \
        -o "$output" -w '%{http_code}' "$url" 2>"$TMP_DIR/curl.err")" || {
        log_error "HUB_UNREACHABLE: $(tail -c 240 "$TMP_DIR/curl.err" 2>/dev/null)"
        return 1
    }
    case "$code" in
        200|201) clear_last_error; return 0 ;;
        401|403)
            log_error "BAD_HOOK_TOKEN: Hub HTTP $code ($(tail -c 240 "$output" 2>/dev/null))"
            return 2
            ;;
        404)
            log_error "HUB_API_MISSING: Hub HTTP 404; update Hub to v0.8.4+"
            return 1
            ;;
        *)
            log_error "HUB_HTTP_ERROR: HTTP $code ($(tail -c 240 "$output" 2>/dev/null))"
            return 1
            ;;
    esac
}

fetch_commands() {
    http_get "$TMP_DIR/commands.json" \
        "$HUB_URL/api/router/portmaps/commands?router=$ROUTER_NAME&limit=20"
}

apply_commands() {
    "$BIN" agent-apply --socket "$SOCKET" --file "$TMP_DIR/commands.json" \
        > "$TMP_DIR/acks.json" 2> "$TMP_DIR/apply.err" || {
        log_error "RELAY_APPLY_FAILED: $(tail -c 300 "$TMP_DIR/apply.err" 2>/dev/null)"
        return 1
    }
    http_post_file "$TMP_DIR/acks.json" "$TMP_DIR/ack-response.json" \
        "$HUB_URL/api/router/portmaps/ack?router=$ROUTER_NAME"
}

push_status() {
    "$BIN" ctl --socket "$SOCKET" '{"action":"status"}' \
        > "$TMP_DIR/status.json" 2> "$TMP_DIR/status.err" || {
        log_error "RELAY_STATUS_FAILED: $(tail -c 300 "$TMP_DIR/status.err" 2>/dev/null)"
        return 1
    }
    http_post_file "$TMP_DIR/status.json" "$TMP_DIR/status-response.json" \
        "$HUB_URL/api/router/portmaps/status?router=$ROUTER_NAME"
}

auth_test() {
    mkdir -p "$TMP_DIR"
    validate_config || return 1
    http_get "$TMP_DIR/auth-test.json" \
        "$HUB_URL/api/router/portmaps/auth-test?router=$ROUTER_NAME"
    rc=$?
    cat "$TMP_DIR/auth-test.json" 2>/dev/null || true
    return "$rc"
}

run_once() {
    mkdir -p "$TMP_DIR"
    validate_config || return 1
    fetch_commands
    rc=$?
    [ "$rc" -eq 0 ] && apply_commands
    [ "$rc" -eq 2 ] && return 2
    push_status
}

daemon_loop() {
    mkdir -p "$TMP_DIR"
    validate_config || exit 1
    last_status=0
    while :; do
        now="$(date +%s)"
        fetch_commands
        fetch_rc=$?
        if [ "$fetch_rc" -eq 0 ]; then
            apply_commands
        elif [ "$fetch_rc" -eq 2 ]; then
            sleep "$AUTH_BACKOFF_SEC"
            continue
        fi
        if [ $((now - last_status)) -ge "$STATUS_INTERVAL" ]; then
            push_status
            status_rc=$?
            [ "$status_rc" -eq 2 ] && sleep "$AUTH_BACKOFF_SEC"
            last_status="$now"
        fi
        sleep "$POLL_INTERVAL"
    done
}

case "${1:-daemon}" in
    once) run_once ;;
    test) auth_test ;;
    version) echo "labrelay-agent $AGENT_VERSION protocol $PROTOCOL_VERSION" ;;
    daemon) daemon_loop ;;
    *) echo "Usage: $0 [daemon|once|test|version]" >&2; exit 2 ;;
esac
