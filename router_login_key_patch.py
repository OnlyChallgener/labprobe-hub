"""BE72 login-key compatibility for the direct eWeb client.

Some Reyee/H3 firmware embeds a per-page GibberishAES key in the login HTML.
BE72 Pro firmware does not expose that key in the returned HTML, but uses the
legacy Reyee eWeb AES password that LabProbe already used successfully for
``/cgi-bin/luci/api/auth``.  Keep dynamic-key discovery when available and only
fall back when the page was fetched successfully but contained no key.
"""
from __future__ import annotations

from typing import Any, Dict

import router_rpc_v010 as runtime
from router_rpc import LOGIN_AES_PASSWORD, RouterRpcError


_ORIGINAL_FETCH_LOGIN_KEY = runtime.StableRuijieRouterClient._fetch_login_key


def _fetch_login_key_with_be72_fallback(self: Any, cfg: Dict[str, Any]) -> str:
    try:
        return _ORIGINAL_FETCH_LOGIN_KEY(self, cfg)
    except RouterRpcError as exc:
        if getattr(exc, "code", "") != "LOGIN_KEY_NOT_FOUND":
            raise
        self.logger.info(
            "router eweb login page has no dynamic AES key; using BE72 compatible key"
        )
        return LOGIN_AES_PASSWORD


def install_router_login_key_patch() -> None:
    """Install once before the router blueprint creates its client."""
    client_class = runtime.StableRuijieRouterClient
    if getattr(client_class, "_labprobe_be72_key_patch", False):
        return
    client_class._fetch_login_key = _fetch_login_key_with_be72_fallback
    client_class._labprobe_be72_key_patch = True
