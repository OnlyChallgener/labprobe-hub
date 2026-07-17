# LabProbe 变更记录

## 0.9.x（当前开发分支）

- Hub 改为通用 Linux AMD64/ARM64 部署，并统一相对数据目录。
- 数据存储迁移到 SQLite，加入版本迁移、备份和校验机制。
- APP 同步改为首次全量、后续增量和定期校准。
- APP 与锐捷 Rust Agent 支持独立配对码、Client Token 和单独吊销。
- 锐捷侧业务采集、推送、重试和诊断统一由 Rust Agent 接管。
- 安装、升级、修复、重新配对和卸载统一使用 `scripts/labprobe-install.sh`。
- APP 与 Rust 更新清单由 `scripts/build_update_bundle.py` 统一生成。

## 0.7.x–0.8.x（历史版本）

早期 DSM/NAS 专用部署说明、逐版本发布记录和 Shell 采集方案已合并归档。为避免继续误用旧入口，仓库不再保留这些分散文件；完整历史仍可从 Git 提交记录查看。
