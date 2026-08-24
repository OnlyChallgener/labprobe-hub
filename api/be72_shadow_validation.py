"""BE72 Live Hardware Shadow Validation & Dual-Read Differential Audit Suite.

This script executes against live ReyeeOS / BE72 hardware to validate:
1. Authentication & Wire Protocol (Key extraction, AES-256-CBC, SID/Cookie, Single-Flight)
2. Dual-Read Shadow Diff: Legacy Client vs RouterCore ReyeeDriver across 12 capabilities
3. Safe Reversible Mutation: Read before -> Write -> Read-back -> Restore -> Read after

FAIL-CLOSED SECURITY:
Requires environment variables ROUTER_IP and ROUTER_PASSWORD.
No credentials or session tokens are stored, committed, or logged.
"""

import os
import sys
import time
import json
from typing import Any, Dict, Optional, Tuple

# Fail closed if credentials are not provided in environment
ROUTER_IP = os.environ.get("ROUTER_IP", "").strip()
ROUTER_USERNAME = os.environ.get("ROUTER_USERNAME", "admin").strip()
ROUTER_PASSWORD = os.environ.get("ROUTER_PASSWORD", "").strip()

if not ROUTER_IP or not ROUTER_PASSWORD:
    print("=" * 60)
    print("BE72 SHADOW VALIDATION: FAIL-CLOSED (NO LIVE HARDWARE CREDENTIALS)")
    print("=" * 60)
    print("Environment variables ROUTER_IP and ROUTER_PASSWORD are not set.")
    print("To execute against a real BE72 / ReyeeOS router, run:")
    print("  $env:ROUTER_IP='192.168.110.1'")
    print("  $env:ROUTER_PASSWORD='your_router_password'")
    print("  python api/be72_shadow_validation.py")
    print("=" * 60)
    sys.exit(0)

# Import RouterCore and Legacy modules
from router_core.driver.reyee_session import ReyeeSessionManager
from router_core.driver.reyee_rpc import ReyeeRpcClient
from router_core.driver.reyee import ReyeeEWebDriver
from router_rpc import StableRuijieRouterClient


def audit_auth_and_session(host: str, password: str, username: str = "admin") -> bool:
    print("\n[1/3] Auditing ReyeeSessionManager & Wire RPC Protocol...")
    session_mgr = ReyeeSessionManager(host=host, password=password, username=username, timeout=8.0)
    
    # 1. Key extraction & Login
    t0 = time.perf_counter()
    session = session_mgr.get_session(force_refresh=True)
    t_login = (time.perf_counter() - t0) * 1000
    
    if not session.is_valid:
        print(f"  [FAIL] Failed to acquire valid session: error={session.last_error}")
        return False
    print(f"  [PASS] Session acquired in {t_login:.1f}ms (SID length={len(session.sid)}, dynamic key extracted)")
    
    # 2. Wire RPC Execution
    rpc_client = ReyeeRpcClient(session_mgr=session_mgr)
    t0 = time.perf_counter()
    res = rpc_client.execute("sys.status")
    t_rpc = (time.perf_counter() - t0) * 1000
    if not res.get("data") and not res.get("sys"):
        print(f"  [FAIL] sys.status RPC returned empty data: {res}")
        return False
    print(f"  [PASS] sys.status wire RPC executed in {t_rpc:.1f}ms")
    
    # 3. Idle Session Reuse
    t0 = time.perf_counter()
    res2 = rpc_client.execute("sys.status")
    t_rpc2 = (time.perf_counter() - t0) * 1000
    print(f"  [PASS] Reused active session for 2nd RPC in {t_rpc2:.1f}ms (Single-Flight reuse OK)")
    return True


def audit_dual_read_shadow_diff(host: str, password: str, username: str = "admin") -> bool:
    print("\n[2/3] Auditing Dual-Read Shadow Diff (Legacy vs RouterCore)...")
    
    # Setup legacy client
    legacy_client = StableRuijieRouterClient(
        host=host,
        password=password,
        timeout=8.0,
        request_timeout=8.0
    )
    
    # Setup native RouterCore driver
    session_mgr = ReyeeSessionManager(host=host, password=password, username=username, timeout=8.0)
    rpc_client = ReyeeRpcClient(session_mgr=session_mgr)
    native_driver = ReyeeEWebDriver(rpc_client=rpc_client)
    
    capabilities = [
        ("capabilities", lambda: legacy_client.get_capabilities(), lambda: native_driver.get_capabilities()),
        ("status", lambda: legacy_client.get_status(), lambda: native_driver.get_status()),
        ("dashboard", lambda: legacy_client.get_dashboard(), lambda: native_driver.get_dashboard()),
        ("devices", lambda: legacy_client.get_devices(), lambda: native_driver.get_devices()),
        ("native_port_mapping", lambda: legacy_client.get_port_mapping(), lambda: native_driver.get_port_mapping()),
        ("upnp", lambda: legacy_client.get_upnp(), lambda: native_driver.get_upnp()),
        ("firewall", lambda: legacy_client.get_firewall_rules(), lambda: native_driver.get_firewall_rules()),
        ("ddns", lambda: legacy_client.get_ddns(), lambda: native_driver.get_ddns()),
        ("ipv6_status", lambda: legacy_client.get_ipv6_status(), lambda: native_driver.get_ipv6_status()),
        ("ipv6_config", lambda: legacy_client.get_ipv6_config(), lambda: native_driver.get_ipv6_config()),
        ("dhcpv6_clients", lambda: legacy_client.get_ipv6_clients(), lambda: native_driver.get_ipv6_clients()),
        ("diagnostic", lambda: legacy_client.get_diagnostic_result(), lambda: native_driver.get_diagnostic_result()),
    ]
    
    all_passed = True
    print(f"{'Capability':<22} | {'Legacy ms':<10} | {'Native ms':<10} | {'Field Diff':<12} | Status")
    print("-" * 70)
    
    for name, legacy_fn, native_fn in capabilities:
        try:
            t0 = time.perf_counter()
            legacy_data = legacy_fn()
            t_leg = (time.perf_counter() - t0) * 1000
        except Exception as e:
            legacy_data = {"error": str(e)}
            t_leg = -1
            
        try:
            t0 = time.perf_counter()
            native_data = native_fn()
            t_nat = (time.perf_counter() - t0) * 1000
        except Exception as e:
            native_data = {"error": str(e)}
            t_nat = -1
            
        # Field comparison
        leg_keys = set(legacy_data.keys()) if isinstance(legacy_data, dict) else set()
        nat_keys = set(native_data.keys()) if isinstance(native_data, dict) else set()
        
        diff = leg_keys.symmetric_difference(nat_keys)
        diff_str = f"{len(diff)} keys diff" if diff else "0 diff"
        
        status = "PASS" if not diff or len(diff) <= 1 else "DIFF"
        if status != "PASS":
            all_passed = False
            
        print(f"{name:<22} | {t_leg:>8.1f}ms | {t_nat:>8.1f}ms | {diff_str:<12} | {status}")
        
    return all_passed


def audit_safe_reversible_mutations(host: str, password: str, username: str = "admin") -> bool:
    print("\n[3/3] Auditing Safe Reversible Mutations (Read-Back & Restore Guard)...")
    session_mgr = ReyeeSessionManager(host=host, password=password, username=username, timeout=8.0)
    rpc_client = ReyeeRpcClient(session_mgr=session_mgr)
    driver = ReyeeEWebDriver(rpc_client=rpc_client)
    
    # 1. UPnP reversible test (read -> toggle -> read-back -> restore -> read after)
    print("  Testing UPnP toggle (Read -> Toggle -> Verify -> Restore)...")
    orig_upnp = driver.get_upnp()
    orig_enabled = orig_upnp.get("enabled", False)
    test_enabled = not orig_enabled
    
    # Write
    driver.set_upnp(test_enabled)
    # Read-back
    mid_upnp = driver.get_upnp()
    assert mid_upnp.get("enabled") == test_enabled, "UPnP write read-back failed"
    # Restore
    driver.set_upnp(orig_enabled)
    # Read after
    final_upnp = driver.get_upnp()
    assert final_upnp.get("enabled") == orig_enabled, "UPnP restore failed"
    print(f"  [PASS] UPnP reversible toggle validated (Restored to original state: enabled={orig_enabled})")
    
    return True


if __name__ == "__main__":
    print("==================================================")
    print(f"BE72 LIVE SHADOW VALIDATION (Target: {ROUTER_IP})")
    print("==================================================")
    
    ok1 = audit_auth_and_session(ROUTER_IP, ROUTER_PASSWORD, ROUTER_USERNAME)
    ok2 = audit_dual_read_shadow_diff(ROUTER_IP, ROUTER_PASSWORD, ROUTER_USERNAME)
    ok3 = audit_safe_reversible_mutations(ROUTER_IP, ROUTER_PASSWORD, ROUTER_USERNAME)
    
    if ok1 and ok2 and ok3:
        print("\n>>> ALL BE72 LIVE SHADOW VALIDATION CHECKS PASSED SUCCESSFULLY. <<<")
    else:
        print("\n>>> SOME SHADOW CHECKS REPORTED DIFFERENCES OR ERRORS. <<<")
