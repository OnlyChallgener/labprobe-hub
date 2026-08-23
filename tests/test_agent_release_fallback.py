from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest import mock

import requests


TEST_ROOT = tempfile.mkdtemp(prefix="labprobe-agent-release-test-")
os.environ["DATA_DIR"] = str(Path(TEST_ROOT) / "data")
os.environ["CONFIG_DIR"] = str(Path(TEST_ROOT) / "config")
os.environ["BACKUPS_DIR"] = str(Path(TEST_ROOT) / "backups")
os.environ["LOGS_DIR"] = str(Path(TEST_ROOT) / "logs")
os.environ["CONFIG_PATH"] = str(Path(TEST_ROOT) / "config" / "config.yaml")
os.environ["APP_TOKEN"] = "test-app-token"
os.environ["HOOK_TOKEN"] = "test-hook-token"

import hub


class FakeManifestResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def release_manifest(version: str = "0.2.24"):
    root = f"https://github.com/OnlyChallgener/labprobe-hub/releases/download/labrelay-v{version}"
    return {
        "schemaVersion": 1,
        "versionName": version,
        "changelog": "Agent reliability update",
        "installUrl": f"{root}/install.sh",
        "binaries": {
            "arm64": {
                "url": f"{root}/labrelay-linux-arm64",
                "sha256": "a" * 64,
            }
        },
    }


def test_agent_manifest_falls_back_to_github_release(monkeypatch):
    primary = "https://updates.example/agent/latest.json"
    github = "https://github.com/OnlyChallgener/labprobe-hub/releases/latest/download/latest.json"
    monkeypatch.setattr(hub, "AGENT_MANIFEST_URL", primary)
    monkeypatch.setattr(hub, "AGENT_GITHUB_MANIFEST_URL", github)
    monkeypatch.setattr(hub, "AGENT_RELEASE_CACHE", {"at": 0.0, "data": None})

    calls = []

    def fake_get(url, **_kwargs):
        calls.append(url)
        if url == primary:
            raise requests.Timeout("primary timed out")
        return FakeManifestResponse(release_manifest())

    with mock.patch.object(hub.requests, "get", side_effect=fake_get):
        manifest = hub.agent_release_manifest(force=True)

    release_root = "https://github.com/OnlyChallgener/labprobe-hub/releases/download/labrelay-v0.2.24"
    assert calls == [primary, github]
    assert manifest["versionName"] == "0.2.24"
    assert manifest["_manifestUrl"] == github
    assert manifest["_installerUrl"] == f"{release_root}/install.sh"
    assert manifest["_repositoryRoot"] == release_root
    assert manifest["_stale"] is False


def test_agent_manifest_uses_stale_cache_when_every_source_is_down(monkeypatch):
    cached = hub._normalized_agent_manifest(
        release_manifest("0.2.21"),
        "https://github.com/OnlyChallgener/labprobe-hub/releases/latest/download/latest.json",
    )
    monkeypatch.setattr(hub, "AGENT_MANIFEST_URL", "https://updates.example/agent/latest.json")
    monkeypatch.setattr(hub, "AGENT_GITHUB_MANIFEST_URL", "https://github.example/latest.json")
    monkeypatch.setattr(hub, "AGENT_RELEASE_CACHE", {"at": 1.0, "data": cached})

    with mock.patch.object(hub.requests, "get", side_effect=requests.Timeout("offline")):
        manifest = hub.agent_release_manifest(force=True)

    assert manifest["versionName"] == "0.2.21"
    assert manifest["_stale"] is True
