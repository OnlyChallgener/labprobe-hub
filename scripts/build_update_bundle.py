#!/usr/bin/env python3
"""Build the canonical LabProbe APP + Agent update repository bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path


DEFAULT_ROOT = "https://lab.net86.dynv6.net:27772"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path, url: str, fallback_url: str = "") -> dict:
    value = {
        "url": url,
        "sha256": sha256(path),
        "sizeBytes": path.stat().st_size,
    }
    if fallback_url:
        value["fallbackUrl"] = fallback_url
    return value


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate one identical update bundle for local, GitHub and Lucky")
    parser.add_argument("--app-apk", required=True, type=Path)
    parser.add_argument("--app-version-name", required=True)
    parser.add_argument("--app-version-code", required=True, type=int)
    parser.add_argument("--agent-arm64", required=True, type=Path)
    parser.add_argument("--agent-version", required=True)
    parser.add_argument("--installer", type=Path, default=Path(__file__).with_name("labprobe-install.sh"))
    parser.add_argument("--output", type=Path, default=Path("update-bundle"))
    parser.add_argument("--root", default=os.environ.get("UPDATE_REPOSITORY_ROOT", DEFAULT_ROOT))
    parser.add_argument("--app-changelog", default="")
    parser.add_argument("--agent-changelog", default="")
    args = parser.parse_args()

    sources = [args.app_apk, args.agent_arm64, args.installer]
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        parser.error("missing input files: " + ", ".join(missing))

    root = args.root.rstrip("/")
    app_dir = args.output / "app"
    agent_dir = args.output / "agent"
    app_dir.mkdir(parents=True, exist_ok=True)
    agent_dir.mkdir(parents=True, exist_ok=True)
    for stale in agent_dir.glob("labrelay-linux-*"):
        if stale.name != "labrelay-linux-arm64":
            stale.unlink()

    apk_name = f"LabProbeApp-v{args.app_version_name}.apk"
    apk = app_dir / apk_name
    arm64 = agent_dir / "labrelay-linux-arm64"
    installer = agent_dir / "install.sh"
    shutil.copy2(args.app_apk, apk)
    shutil.copy2(args.agent_arm64, arm64)
    shutil.copy2(args.installer, installer)

    app_fallback = f"https://github.com/OnlyChallgener/LabProbeApp/releases/latest/download/{apk_name}"
    agent_fallback = "https://github.com/OnlyChallgener/labprobe-hub/releases/latest/download"
    app_meta = artifact(apk, f"{root}/app/{apk_name}", app_fallback)
    update_json = {
        "schemaVersion": 1,
        "versionCode": args.app_version_code,
        "versionName": args.app_version_name,
        "forceUpdate": False,
        "downloadUrl": app_meta["url"],
        "fallbackUrl": app_meta["fallbackUrl"],
        "sha256": app_meta["sha256"],
        "sizeBytes": app_meta["sizeBytes"],
        "changelog": args.app_changelog,
    }
    write_json(app_dir / "update.json", update_json)

    arm_meta = artifact(arm64, f"{root}/agent/{arm64.name}", f"{agent_fallback}/{arm64.name}")
    installer_meta = artifact(installer, f"{root}/agent/install.sh", f"{agent_fallback}/labprobe-install.sh")
    latest_json = {
        "schemaVersion": 1,
        "versionName": args.agent_version,
        "changelog": args.agent_changelog,
        "installUrl": installer_meta["url"],
        "installer": installer_meta,
        "checksumsUrl": f"{root}/agent/checksums.txt",
        "binaries": {"arm64": arm_meta},
    }
    write_json(agent_dir / "latest.json", latest_json)

    checksums = [
        f"{arm_meta['sha256']}  {arm64.name}",
        f"{installer_meta['sha256']}  install.sh",
    ]
    (agent_dir / "checksums.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    print(f"bundle={args.output.resolve()}")
    print(f"app={apk_name} sha256={app_meta['sha256']} sizeBytes={app_meta['sizeBytes']}")
    print(f"agent={args.agent_version} arm64={arm_meta['sizeBytes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
