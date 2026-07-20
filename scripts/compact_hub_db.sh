#!/bin/sh
set -eu

CONTAINER="${1:-labprobe-hub}"
KEEP_REVISIONS="${KEEP_REVISIONS:-1500}"

IMAGE="$(docker inspect -f '{{.Config.Image}}' "$CONTAINER")"
[ -n "$IMAGE" ] || { echo "无法获取容器镜像：$CONTAINER" >&2; exit 1; }

restart_container() {
  docker start "$CONTAINER" >/dev/null 2>&1 || true
}
trap restart_container EXIT INT TERM

echo "停止 $CONTAINER ..."
docker stop "$CONTAINER" >/dev/null

echo "备份、裁剪 revision、执行 VACUUM ..."
docker run --rm \
  --volumes-from "$CONTAINER" \
  --entrypoint python \
  "$IMAGE" \
  /app/scripts/repair_storage.py \
  --database /app/data/labprobe.db \
  --backup-dir /app/backups \
  --keep-revisions "$KEEP_REVISIONS" \
  --vacuum

echo "重新启动 $CONTAINER ..."
docker start "$CONTAINER" >/dev/null
trap - EXIT INT TERM

echo "完成。"
