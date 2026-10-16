#!/bin/sh
# Narrow compatibility guard for deployed relay versions before RDPI recovery.
# It follows existing child_guard configuration; no library or policy writes.
set -u
lock_path=${LABPROBE_RDPI_LOCK:-/tmp/labprobe-rdpi-healthcheck.lock}
mkdir "$lock_path" 2>/dev/null || exit 0
trap 'rmdir "$lock_path" 2>/dev/null || true' EXIT HUP INT TERM

configured=$(uci -q get child_guard.config.rdpi_enable 2>/dev/null) || exit 0
[ "$configured" = 1 ] || exit 0
users=$(uci -q get child_guard.config.user_num 2>/dev/null) || exit 0
case "$users" in ''|*[!0-9]*|0) exit 0;; esac

status=$(ubus -t 3 call sniffer show_abil 2>/dev/null) || exit 1
reference=$(printf '%s' "$status" | jsonfilter -e '@.RDPI' 2>/dev/null) || exit 1
case "$reference" in
0)
    # The firmware uses a reference count; only recover a stopped detector.
    ubus -t 3 call sniffer enable '{"mod":"rdpi"}' >/dev/null || exit 1
    status=$(ubus -t 3 call sniffer show_abil 2>/dev/null) || exit 1
    reference=$(printf '%s' "$status" | jsonfilter -e '@.RDPI' 2>/dev/null) || exit 1
    case "$reference" in ''|*[!0-9]*|0) exit 1;; esac
    logger -t labprobe-rdpi 'Restored configured RDPI after runtime reset' 2>/dev/null || true
    ;;
''|*[!0-9]*) exit 1;;
*) :;;
esac
