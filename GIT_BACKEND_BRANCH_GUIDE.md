# Git 新分支上传

建议分支：

```text
backend/v0.8.4-relay-v0.1.1
```

在家里电脑 Git Bash：

```bash
cd /d/Github/labprobe-hub

git status --short
git fetch origin --prune
git switch main
git pull --ff-only origin main

git switch -c backend/v0.8.4-relay-v0.1.1
```

把完整项目或覆盖文件复制到 `D:\Github\labprobe-hub` 后：

```bash
python -m py_compile hub.py
sh -n scripts/labrelay_agent.sh
sh -n scripts/install_labrelay.sh

git status --short
git diff --stat
git diff --check

git add -A
git commit -m "Upgrade Hub to v0.8.4 and LabRelay agent to v0.1.1"
git push -u origin backend/v0.8.4-relay-v0.1.1
```

然后在 GitHub Actions：

1. 运行 Docker Image，选择该分支。
2. 运行 Build LabRelay Router Binary，选择该分支。
3. Rust workflow 必须通过 `cargo test --all-targets` 后再安装到路由器。
