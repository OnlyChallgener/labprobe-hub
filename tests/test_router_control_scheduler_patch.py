import threading
import time

import router_control_scheduler_patch as scheduler
import router_slow_cache_patch as slow_cache


def test_background_router_refreshes_are_serialized(monkeypatch):
    threads = []

    def fake_start_refresh(client, key, loader):
        thread = threading.Thread(target=loader, daemon=True)
        threads.append(thread)
        thread.start()

    monkeypatch.setattr(slow_cache, "_start_refresh", fake_start_refresh)
    monkeypatch.delattr(slow_cache, "_labprobe_control_scheduler_patch", raising=False)
    scheduler.install_router_control_scheduler_patch()

    state_lock = threading.Lock()
    active = 0
    max_active = 0

    def loader():
        nonlocal active, max_active
        with state_lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.06)
        with state_lock:
            active -= 1
        return True

    slow_cache._start_refresh(object(), "ddns", loader)
    slow_cache._start_refresh(object(), "firewall", loader)
    for thread in threads:
        thread.join(timeout=1)

    assert max_active == 1
