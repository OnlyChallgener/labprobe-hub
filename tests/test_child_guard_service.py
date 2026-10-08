import threading
import time

import pytest


def test_add_retry_reuses_pending_command_only_for_same_router_and_macs(tmp_path):
    store = RouterCommandStore(tmp_path)
    first = store.enqueue("BE50", "add_device", {"macs": ["AA:BB:CC:DD:EE:FF"]})
    store.take("BE50")
    retry = store.enqueue("BE50", "add_device", {"macs": ["aa:bb:cc:dd:ee:ff"]})
    assert retry["id"] == first["id"]
    other = store.enqueue("BE72", "add_device", {"macs": ["aa:bb:cc:dd:ee:ff"]})
    assert other["id"] != first["id"]
    store.acknowledge("BE50", [{"id": first["id"], "ok": True, "result": {"ok": True}}])
    assert store.enqueue("BE50", "add_device", first["payload"])["id"] != first["id"]

from child_guard_service import (
    RouterCommandStore,
    ChildGuardValidationError,
    clean_plan,
    expand_application_rdpi_ids,
    validate_uid,
)


def test_catalog_application_expands_to_all_rdpi_ids():
    values = expand_application_rdpi_ids([
        {
            "id": "wechat",
            "name": "微信",
            "rdpiIds": ["7-1-2-0", "7-1-2-3", "7-1-2-12", "7-1-2-14"],
        },
        {"id": "duplicate", "rdpiIds": ["7-1-2-0"]},
    ])
    assert values == ["7-1-2-0", "7-1-2-3", "7-1-2-12", "7-1-2-14"]


def test_router_hex_uid_is_normalized_but_custom_uid_is_preserved():
    assert validate_uid("abcdef0123456789abcdef0123456789") == "ABCDEF0123456789ABCDEF0123456789"
    assert validate_uid("custom_Device-1") == "custom_Device-1"


def test_clean_plan_rejects_application_mode_without_signatures():
    with pytest.raises(ChildGuardValidationError):
        clean_plan({
            "name": "未映射应用",
            "startTime": "08:00",
            "endTime": "09:00",
            "weekdays": ["mon"],
            "mode": "app_allowlist",
            "applications": [],
        })


def test_plan_contract_keeps_device_hint_and_catalog_metadata():
    value = clean_plan({
        "name": "微信计划",
        "enabled": True,
        "startTime": "08:00",
        "endTime": "09:00",
        "weekdays": ["mon", "tue"],
        "mode": "app_allowlist",
        "deviceMac": "AA:BB:CC:DD:EE:FF",
        "deviceName": "很长的设备名称",
        "applications": [{"id": "wechat", "name": "微信", "rdpiIds": ["7-1-2-0", "7-1-2-3"]}],
    })
    assert value["deviceMac"] == "aa:bb:cc:dd:ee:ff"
    assert value["applicationRdpiIds"] == ["7-1-2-0", "7-1-2-3"]
    assert value["applications"][0]["id"] == "wechat"


def test_command_queue_delivers_and_acknowledges(tmp_path):
    store = RouterCommandStore(tmp_path)
    command = store.enqueue("BE72", "get_capabilities", {})
    delivered = store.take("BE72")
    assert delivered[0]["id"] == command["id"]
    assert store.acknowledge("BE72", [{
        "id": command["id"],
        "ok": True,
        "result": {"ok": True, "capabilities": {"available": True}},
    }]) == 1
    result = store.wait(command["id"], 0.1)
    assert result.state == "done"
    assert result.result["capabilities"]["available"] is True


def test_wait_wakes_after_agent_ack(tmp_path):
    store = RouterCommandStore(tmp_path)
    command = store.enqueue("BE72", "get_users", {})

    def worker():
        time.sleep(0.02)
        store.take("BE72")
        store.acknowledge("BE72", [{"id": command["id"], "ok": True,
                                    "result": {"ok": True, "devices": []}}])

    thread = threading.Thread(target=worker)
    thread.start()
    result = store.wait(command["id"], 1.0)
    thread.join()
    assert result.state == "done"
    assert result.result["devices"] == []


def test_manual_writes_pass_pending_reads_but_keep_write_order(tmp_path):
    store = RouterCommandStore(tmp_path)
    read = store.enqueue("BE72", "get_users", {})
    add = store.enqueue("BE72", "add_device", {"macs": ["aa:bb:cc:dd:ee:ff"]})
    remove = store.enqueue("BE72", "remove_device", {"uid": "test"})
    assert [r["id"] for r in store.take("BE72")] == [add["id"], remove["id"], read["id"]]


def test_identical_reads_merge_but_post_write_refresh_is_new(tmp_path):
    store = RouterCommandStore(tmp_path)
    first = store.enqueue("BE72", "get_users", {})
    assert store.enqueue("BE72", "get_users", {})["id"] == first["id"]
    store.enqueue("BE72", "remove_device", {"uid": "test"})
    newer = store.enqueue("BE72", "get_users", {})
    assert newer["id"] != first["id"]
    assert newer["sequence"] > first["sequence"]


def test_membership_result_carries_request_order_and_duplicate_ack_is_noop(tmp_path):
    store = RouterCommandStore(tmp_path)
    first = store.enqueue("BE72", "get_users", {})
    ack = [{"id": first["id"], "ok": True, "result": {"ok": True, "devices": []}}]
    assert store.acknowledge("BE72", ack) == 1
    assert store.result(first["id"]).result["membershipVersion"] == first["sequence"]
    assert store.acknowledge("BE72", ack) == 0
