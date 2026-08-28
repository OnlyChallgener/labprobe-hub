import pytest

import hub as hub_module


@pytest.fixture()
def hub_app(monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "current-app-token")
    monkeypatch.setenv("HOOK_TOKEN", "current-hook-token")
    monkeypatch.delenv("APP_TOKEN_PREVIOUS", raising=False)
    monkeypatch.delenv("HOOK_TOKEN_PREVIOUS", raising=False)
    hub_module._AUTH_FAILURES.clear()
    hub_module._AUTH_BLOCKED.clear()
    yield hub_module
    hub_module._AUTH_FAILURES.clear()
    hub_module._AUTH_BLOCKED.clear()


def test_previous_app_token_is_accepted_during_rotation(hub_app, monkeypatch):
    monkeypatch.setenv("APP_TOKEN_PREVIOUS", "old-app-token")
    app = hub_app.app
    with app.test_request_context("/", headers={"Authorization": "Bearer old-app-token"}):
        assert hub_module.check_app_token() is True
    with app.test_request_context("/", headers={"Authorization": "Bearer current-app-token"}):
        assert hub_module.check_app_token() is True
    with app.test_request_context("/", headers={"Authorization": "Bearer unrelated"}):
        assert hub_module.check_app_token() is False


def test_previous_hook_token_is_accepted_for_hook_auth(hub_app, monkeypatch):
    monkeypatch.setenv("HOOK_TOKEN_PREVIOUS", "old-hook-token")
    app = hub_app.app
    with app.test_request_context("/", headers={"X-LabProbe-Token": "old-hook-token"}):
        assert hub_module.check_hook_token() is True


def test_failed_attempts_trigger_and_expire_throttle(hub_app):
    app = hub_app.app
    with app.test_request_context("/", headers={"Authorization": "Bearer wrong"}):
        for _ in range(15):
            assert hub_module.check_app_token() is False
        assert hub_module._auth_throttled() is True
        # While blocked, even a valid token is refused.
        with app.test_request_context("/", headers={"Authorization": "Bearer current-app-token"}):
            assert hub_module.check_app_token() is False
    # Expire the block: valid tokens pass again and clear the failure window.
    hub_module._AUTH_BLOCKED.clear()
    with app.test_request_context("/", headers={"Authorization": "Bearer current-app-token"}):
        assert hub_module.check_app_token() is True
