#!/usr/bin/env python3
from pathlib import Path

path = Path('scripts/labprobe-install.sh')
text = path.read_text(encoding='utf-8')

old = '''  for legacy_init in "$BACKUP"/*.legacy-init; do
    [ -f "$legacy_init" ] || continue
    old_name="$(basename "$legacy_init" .legacy-init)"
    mv "$legacy_init" "/etc/init.d/$old_name"
    chmod 0755 "/etc/init.d/$old_name"
    "/etc/init.d/$old_name" enable >/dev/null 2>&1 || true
    "/etc/init.d/$old_name" start >/dev/null 2>&1 || true
  done
  [ -x "$INIT_SCRIPT" ] && "$INIT_SCRIPT" restart >/dev/null 2>&1 || true
'''
new = '''  if [ "${HAD_OLD_INIT:-0}" = "1" ]; then
    # We upgraded from the unified labprobe service. Never resurrect legacy
    # split labrelay/labrelay_agent services during rollback, otherwise procd
    # will run two daemons and two agents against the same socket/ports.
    rm -f /etc/init.d/labrelay /etc/init.d/labrelay_agent \
      /etc/rc.d/S??labrelay /etc/rc.d/K??labrelay \
      /etc/rc.d/S??labrelay_agent /etc/rc.d/K??labrelay_agent
  else
    # First migration from the legacy split services: restore them only when
    # no unified labprobe service existed before the failed install.
    for legacy_init in "$BACKUP"/*.legacy-init; do
      [ -f "$legacy_init" ] || continue
      old_name="$(basename "$legacy_init" .legacy-init)"
      mv "$legacy_init" "/etc/init.d/$old_name"
      chmod 0755 "/etc/init.d/$old_name"
      "/etc/init.d/$old_name" enable >/dev/null 2>&1 || true
      "/etc/init.d/$old_name" start >/dev/null 2>&1 || true
    done
  fi
  [ -x "$INIT_SCRIPT" ] && "$INIT_SCRIPT" restart >/dev/null 2>&1 || true
'''

if old not in text:
    raise SystemExit('missing legacy rollback block')
text = text.replace(old, new, 1)
path.write_text(text, encoding='utf-8')
print('installer rollback legacy service resurrection fixed')
