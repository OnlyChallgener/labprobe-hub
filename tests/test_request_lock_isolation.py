"""Regression tests for request-wide DATA_LOCK isolation.

These tests exercise only the Flask request-lock hook.  They deliberately do
not call the route handlers, so the regression suite stays deterministic and
never performs router, STUN, WireGuard, Android, or Gradle work.
"""

import threading

import pytest
from flask import g

import hub


def _request_lock_is_acquired(path: str, method: str = "GET") -> bool:
    """Run the production before-request hook in an isolated request context."""
    with hub.app.test_request_context(path, method=method):
        hub.lock_request_data()
        # Flask invokes the production teardown hook when this context exits,
        # which releases DATA_LOCK for serialized requests.
        return bool(getattr(g, "data_lock_acquired", False))


@pytest.mark.parametrize(
    ("path", "method"),
    [
        ("/api/ai/notifications/stream", "GET"),
        ("/api/ai/notifications", "GET"),
        ("/api/agent/update/status", "GET"),
        ("/health", "GET"),
        ("/api/ai/chat", "POST"),
        ("/api/stun", "GET"),
        ("/api/stun/rule-1", "PUT"),
        ("/api/stun/rule-1", "DELETE"),
        ("/api/router/stun", "GET"),
        ("/api/router/stun/rule-1", "PUT"),
        ("/api/wireguard", "GET"),
        ("/api/wireguard/server", "PUT"),
        ("/api/router/wireguard", "GET"),
        ("/api/router/wireguard/server", "PUT"),
        ("/api/tcp-session-test/start", "POST"),
        ("/api/router/tcp-session-test/status", "POST"),
    ],
)
def test_long_lived_and_router_io_paths_do_not_acquire_request_wide_data_lock(path, method):
    """Long streams and service-owned router IO must not starve the Hub."""
    assert _request_lock_is_acquired(path, method) is False


@pytest.mark.parametrize(
    ("path", "method"),
    [
        ("/api/status/refresh", "POST"),
        ("/api/events", "POST"),
        ("/api/stun-proxy", "POST"),
    ],
)
def test_ordinary_state_writes_remain_serialized_by_data_lock(path, method):
    """Non-streaming state writes retain request-wide serialization."""
    assert _request_lock_is_acquired(path, method) is True


def test_busy_request_data_lock_returns_bounded_503(monkeypatch):
    """A wedged legacy request must not make every follower wait forever."""
    entered = threading.Event()
    release = threading.Event()

    def hold_lock():
        with hub.DATA_LOCK:
            entered.set()
            release.wait(timeout=2)

    owner = threading.Thread(target=hold_lock, daemon=True)
    owner.start()
    assert entered.wait(timeout=1)
    monkeypatch.setattr(hub, "DATA_LOCK_REQUEST_TIMEOUT_SECONDS", 0.01)
    try:
        with hub.app.test_request_context("/api/status"):
            response, status = hub.lock_request_data()
            assert status == 503
            assert response.get_json()["error"] == "HUB_DATA_BUSY"
            assert response.headers["Retry-After"] == "2"
            assert getattr(g, "data_lock_acquired", False) is False
    finally:
        release.set()
        owner.join(timeout=1)
