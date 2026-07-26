import threading
import time

import pytest

import router_rpc
from router_control_actor_patch import (
    PRIORITY_BACKGROUND,
    PRIORITY_COMMAND,
    RouterControlActor,
)


def test_background_sync_yields_while_user_command_is_active():
    actor = RouterControlActor()
    entered = threading.Event()
    release = threading.Event()
    result = []

    def command():
        entered.set()
        release.wait(2)
        return "ok"

    thread = threading.Thread(
        target=lambda: result.append(actor.submit(PRIORITY_COMMAND, "command", command)),
        daemon=True,
    )
    thread.start()
    assert entered.wait(1)

    with pytest.raises(router_rpc.RouterRpcError) as raised:
        actor.submit(PRIORITY_BACKGROUND, "background", lambda: "should-not-run")
    assert raised.value.code == "BACKGROUND_DEFERRED"

    release.set()
    thread.join(2)
    assert result == ["ok"]


def test_foreground_commands_are_serialized():
    actor = RouterControlActor()
    first_entered = threading.Event()
    release_first = threading.Event()
    order = []

    def first():
        order.append("first-start")
        first_entered.set()
        release_first.wait(2)
        order.append("first-end")

    def second():
        order.append("second")

    first_thread = threading.Thread(
        target=lambda: actor.submit(PRIORITY_COMMAND, "first", first),
        daemon=True,
    )
    second_thread = threading.Thread(
        target=lambda: actor.submit(PRIORITY_COMMAND, "second", second),
        daemon=True,
    )
    first_thread.start()
    assert first_entered.wait(1)
    second_thread.start()
    time.sleep(0.05)
    assert order == ["first-start"]
    release_first.set()
    first_thread.join(2)
    second_thread.join(2)
    assert order == ["first-start", "first-end", "second"]
