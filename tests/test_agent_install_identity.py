import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_installer_rejects_implicit_agent_identity_change(tmp_path):
    config = tmp_path / "agent.json"
    saved = {
        "hubUrl": "https://hub.example.test",
        "hookToken": "saved-token",
        "routerName": "saved-router",
    }
    config.write_text(json.dumps(saved), encoding="utf-8")
    installer = tmp_path / "install.sh"
    source = (ROOT / "agent" / "install.sh").read_text(encoding="utf-8")
    installer.write_text(source.replace("/etc/labprobe/agent.json", config.as_posix()), encoding="utf-8")
    env = {**os.environ, "LABRELAY_ALLOW_IDENTITY_CHANGE": "0"}

    result = subprocess.run(
        ["sh", str(installer), "https://other.example.test", "saved-token", "saved-router"],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )

    assert result.returncode != 0
    assert "existing Agent identity differs" in result.stderr
    assert json.loads(config.read_text(encoding="utf-8")) == saved
