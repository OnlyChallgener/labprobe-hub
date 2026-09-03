import re
from pathlib import Path

def test_cargo_toml_version():
    cargo_path = Path("labrelay/Cargo.toml")
    assert cargo_path.exists(), "Cargo.toml must exist"
    text = cargo_path.read_text(encoding="utf-8")
    assert 'version = "0.2.44"' in text, "Cargo.toml must specify version 0.2.44"

def test_cargo_lock_version():
    lock_path = Path("labrelay/Cargo.lock")
    assert lock_path.exists(), "Cargo.lock must exist"
    text = lock_path.read_text(encoding="utf-8")
    assert 'name = "labrelay"\nversion = "0.2.44"' in text, "Cargo.lock must record version 0.2.44"

def test_tcp_session_test_safety_guards():
    rs_path = Path("labrelay/src/tcp_session_test.rs")
    assert rs_path.exists(), "tcp_session_test.rs must exist"
    content = rs_path.read_text(encoding="utf-8")

    # 1. ExtremeNoTrackGuard existence and implementation
    assert "struct ExtremeNoTrackGuard" in content, "ExtremeNoTrackGuard must be defined"
    assert 'NOTRACK' in content, "NOTRACK target rule must be present"
    assert 'labprobe-peak' in content, "labprobe-peak comment tag must be present"
    assert 'impl Drop for ExtremeNoTrackGuard' in content, "ExtremeNoTrackGuard must implement Drop for RAII cleanup"
    assert 'ExtremeNoTrackGuard::activate(address)' in content, "ExtremeNoTrackGuard must be activated per family run"

    # 2. Socket buffer clamping and linger=0
    assert 'socket.set_recv_buffer_size(2048)' in content, "Socket receive buffer must be clamped to 2048 bytes"
    assert 'socket.set_send_buffer_size(2048)' in content, "Socket send buffer must be clamped to 2048 bytes"
    assert 'set_linger(Some(Duration::ZERO))' in content, "Connected socket must set linger(0) for instant release"

    # 3. System reserved port range
    assert 'first.max(1500)' in content, "Must reserve lower ports up to 1500 for system daemons"
    assert 'last.min(64999)' in content, "Must reserve higher ports above 64999 for outgoing system traffic"

    # 4. Memory floor
    assert 'const EXTREME_MEMORY_FLOOR_MB: usize = 150;' in content, "Extreme memory floor must be at least 150MB"

    # 5. Unit test in rust
    assert 'available_source_ports_preserves_system_reserved_ranges' in content, "Unit test for port bounds must be present"

if __name__ == "__main__":
    test_cargo_toml_version()
    test_cargo_lock_version()
    test_tcp_session_test_safety_guards()
    print("ALL PYTHON RELAY 0.2.44 SAFETY TESTS PASSED!")
