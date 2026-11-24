#!/bin/sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if opkg status zerotier-one-static 2>/dev/null | grep -q '^Status: .* installed$'; then
    exec /usr/sbin/zerotier-update "$here"
fi
exec sh "$here/zerotier-update" --bootstrap "$here"
