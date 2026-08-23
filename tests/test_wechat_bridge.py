import json
import subprocess

from flask import Flask

from assistant.wechat import (
    INSTALL_CONFIRMATION,
    OpenClawWeChatBridge,
    create_wechat_blueprint,
)
from assistant.storage import AIStore


def _client(bridge, authorized=True):
    app = Flask(__name__)
    app.register_blueprint(create_wechat_blueprint(check_app_token=lambda: authorized, bridge=bridge))
    return app.test_client()


def test_wechat_status_requires_app_token():
    client = _client(OpenClawWeChatBridge(), authorized=False)
    assert client.get("/api/ai/wechat/status").status_code == 401


def test_wechat_install_requires_explicit_confirmation():
    bridge = OpenClawWeChatBridge()
    bridge.cli_path = "openclaw"
    client = _client(bridge)
    assert client.post("/api/ai/wechat/install", json={}).status_code == 409


def test_wechat_qr_flow_never_returns_bot_token():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if "web.login.start" in command:
            body = {"qrDataUrl": "https://example.invalid/qr", "botToken": "must-not-leak"}
        elif "web.login.wait" in command:
            body = {"connected": True, "accountId": "bot-id", "botToken": "must-not-leak"}
        else:
            body = {"ok": True}
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(body), stderr="")

    bridge = OpenClawWeChatBridge(runner=runner)
    bridge.cli_path = "openclaw"
    client = _client(bridge)
    started = client.post("/api/ai/wechat/login/start")
    assert started.status_code == 200
    assert started.json["qrContent"] == "https://example.invalid/qr"
    assert "botToken" not in started.json
    completed = client.post("/api/ai/wechat/login/wait", json={"loginId": started.json["loginId"]})
    assert completed.status_code == 200
    assert completed.json["connected"] is True
    assert "botToken" not in completed.json
    assert all(isinstance(command, list) for command in calls)


def test_wechat_install_uses_only_fixed_commands():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='{"ok":true}', stderr="")

    bridge = OpenClawWeChatBridge(runner=runner)
    bridge.cli_path = "openclaw"
    client = _client(bridge)
    response = client.post(
        "/api/ai/wechat/install",
        json={"confirmation": INSTALL_CONFIRMATION, "command": "malicious"},
    )
    assert response.status_code == 200
    assert calls[0][1:] == ["plugins", "install", "@tencent-weixin/openclaw-weixin"]


def test_wechat_notification_target_is_not_interpreted_as_a_command():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='{"messageId":"m1"}', stderr="")

    bridge = OpenClawWeChatBridge(runner=runner)
    bridge.cli_path = "openclaw"
    result = bridge.send_message("user_123@im.bot", "设备已上线")
    assert result["ok"] is True
    assert calls[0][1:] == [
        "message", "send", "--channel", "openclaw-weixin",
        "--target", "user_123@im.bot", "--message", "设备已上线", "--json",
    ]

    try:
        bridge.send_message("--target\nattacker", "bad")
    except Exception:
        pass
    else:
        raise AssertionError("invalid notification target must be rejected")


def test_wechat_notification_delivery_is_deduplicated_and_audited(tmp_path):
    store = AIStore(tmp_path / "ai.db")
    store.initialize()
    notification_id = store.add_notification("device", "NAS 上线", "NAS 已上线", "event:1")
    assert notification_id is not None
    store.queue_notification_delivery(notification_id, "openclaw-weixin", "user_123@im.bot")
    store.queue_notification_delivery(notification_id, "openclaw-weixin", "user_123@im.bot")
    due = store.list_due_notification_deliveries()
    assert len(due) == 1
    store.finish_notification_delivery(due[0]["id"], True)
    assert store.list_due_notification_deliveries() == []
