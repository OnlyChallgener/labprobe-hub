#!/usr/bin/env python3
from pathlib import Path

path = Path('scripts/labprobe-install.sh')
text = path.read_text(encoding='utf-8')

old = 'TMP_SUM="/tmp/labrelay.new.sha256"\nUPDATE_ROOT='
new = 'TMP_SUM="/tmp/labrelay.new.sha256"\nLOCAL_BINARY="${LABRELAY_BINARY:-}"\nUPDATE_ROOT='
if old not in text:
    raise SystemExit('missing TMP_SUM insertion point')
text = text.replace(old, new, 1)

needle = '''download_binary() {\n  filename="labrelay-linux-$ARCH"\n  url="$AGENT_BASE/$filename"\n  rm -f "$TMP_BIN" "$TMP_SUM"\n  download_visible "$url" "$TMP_BIN" " Rust Agent"\n  download_visible "$AGENT_BASE/checksums.txt" "$TMP_SUM" " SHA256校验文件"\n  say "正在校验 Rust Agent SHA256"\n  expected="$(awk -v name="$filename" '$2 == name || $2 == "*" name {print $1; exit}' "$TMP_SUM")"\n  actual="$(sha256sum "$TMP_BIN" | awk '{print $1}')"\n  [ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "SHA256校验失败：下载文件可能不完整或已被修改"\n  say "SHA256校验通过：$actual"\n  chmod 0755 "$TMP_BIN"\n}\n'''
addition = needle + '''\nprepare_binary() {\n  if [ -n "$LOCAL_BINARY" ]; then\n    [ -f "$LOCAL_BINARY" ] || fail "指定的本地 Rust Agent 不存在：$LOCAL_BINARY"\n    [ -s "$LOCAL_BINARY" ] || fail "指定的本地 Rust Agent 为空：$LOCAL_BINARY"\n    say "使用本地 Rust Agent：$LOCAL_BINARY"\n    rm -f "$TMP_BIN" "$TMP_SUM"\n    cp "$LOCAL_BINARY" "$TMP_BIN" || fail "复制本地 Rust Agent 失败：$LOCAL_BINARY"\n    chmod 0755 "$TMP_BIN"\n    local_version="$("$TMP_BIN" version 2>/dev/null || "$TMP_BIN" --version 2>/dev/null || true)"\n    [ -n "$local_version" ] || fail "指定的本地文件不是可运行的 LabRelay：$LOCAL_BINARY"\n    actual="$(sha256sum "$TMP_BIN" | awk '{print $1}')"\n    say "本地 Rust Agent 已校验：$local_version"\n    say "本地 Rust Agent SHA256：$actual"\n    return 0\n  fi\n  download_binary\n}\n'''
if needle not in text:
    raise SystemExit('missing download_binary block')
text = text.replace(needle, addition, 1)

old = '''INSTALL_STAGE="下载并校验 ARM64 Agent"\ndownload_binary\n'''
new = '''if [ -n "$LOCAL_BINARY" ]; then\n  INSTALL_STAGE="校验本地 ARM64 Agent"\nelse\n  INSTALL_STAGE="下载并校验 ARM64 Agent"\nfi\nprepare_binary\n'''
if old not in text:
    raise SystemExit('missing main download call')
text = text.replace(old, new, 1)

path.write_text(text, encoding='utf-8')
print('installer local binary override patched')
