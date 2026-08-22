"""IPv6 read/modify/write service using the shared router-control client."""
from __future__ import annotations

import time
from typing import Any, Dict, List

from router_rpc import RouterRpcError

from .mapper import map_clients, map_config, map_status, merge_config
from .models import Dhcpv6Client, Ipv6Config, Ipv6Status, Ipv6ValidationError


class Ipv6Service:
    def __init__(self, client: Any):
        self.client = client

    def status(self) -> Ipv6Status:
        return map_status(self.client.rpc("devSta.get", "ipinfo6"))

    def config(self) -> Ipv6Config:
        return map_config(self._read_full_config())

    def clients(self) -> List[Dhcpv6Client]:
        raw = self.client.rpc(
            "devSta.get",
            "dhcp_lease6",
            {"index": 1, "size": 100, "macaddr": ""},
        )
        return map_clients(raw)

    def update_config(self, requested: Any) -> Dict[str, Any]:
        with self.client.write_lock:
            current = self._read_full_config()
            payload = merge_config(current, requested)
            write_result = self.client.rpc("devConfig.set", "network6", payload)
            self._assert_write_success(write_result)
            verified = map_config(self._read_full_config())
        return {"config": verified, "verifiedAt": int(time.time())}

    def _read_full_config(self) -> Dict[str, Any]:
        raw = self.client.rpc("devConfig.get", "network6")
        if not isinstance(raw, dict):
            raise RouterRpcError("路由器未返回完整 network6 配置", "IPV6_CONFIG_INVALID", 502)
        return raw

    @staticmethod
    def _assert_write_success(result: Any) -> None:
        if not isinstance(result, dict):
            return
        rcode = str(result.get("rcode") or "").strip().lower()
        if rcode not in {"", "0", "00000000", "success"}:
            message = str(result.get("message") or "路由器拒绝保存 IPv6 配置").strip()
            raise RouterRpcError(message, "IPV6_SAVE_REJECTED", 409)


__all__ = ["Ipv6Service", "Ipv6ValidationError"]
