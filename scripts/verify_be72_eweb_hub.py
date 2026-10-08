"""Read-only live checks plus invalid mutation checks (no configuration changes)."""
from __future__ import annotations
import gzip
import hashlib
import json
import time
from pathlib import Path
import requests
from router_core.driver.reyee_session import ReyeeSessionManager


def verify(base: str, password: str) -> dict:
    session = requests.Session()
    session.trust_env = False
    manager = ReyeeSessionManager(address=base, password=password, username="admin",
                                  http_timeout=(4, 8), session_factory=lambda: session)
    auth = manager.get_session()
    url = base + "/cgi-bin/luci/api/labprobe?auth=" + auth.sid
    headers = {"X-LabProbe-Eweb": "1", "Origin": base}
    proof = {"read": {}, "negative": {}, "assets": {}}

    def call(op, payload=None, ident=None, custom_headers=None, authenticated=True):
        started = time.monotonic()
        response = session.post(url if authenticated else base + "/cgi-bin/luci/api/labprobe",
                                headers=headers if custom_headers is None else custom_headers,
                                json={"id": 1, "method": "request", "params": {
                                    "op": op, "payload": payload or {}, "id": ident}}, timeout=(4, 15))
        try:
            data = json.loads(response.content)
        except (ValueError, UnicodeError):
            data = {}
        return response, data, time.monotonic() - started

    results = {}
    for op in ["wg.get", "tcp.get", "ddns.get"]:
        response, data, elapsed = call(op)
        value = data.get("data") or {}
        results[op] = value
        proof["read"][op] = {"status": response.status_code, "ok": value.get("ok"),
                             "httpStatus": value.get("httpStatus"), "seconds": round(elapsed, 2),
                             "keys": list(value), "error": value.get("error"),
                             "contentType": response.headers.get("Content-Type")}
        if op == "wg.get":
            proof["read"][op]["router"] = (value.get("agentStatus") or {}).get("router")
        if op == "ddns.get":
            proof["read"][op]["address"] = value.get("address")
    if results["ddns.get"].get("records"):
        row = results["ddns.get"]["records"][0]
        response, data, _ = call("ddns.credentials", ident=row["id"])
        value = data.get("data") or {}
        credentials = value.get("credentials") or {}
        proof["read"]["ddns.credentials"] = {
            "ok": value.get("ok"), "httpStatus": value.get("httpStatus"),
            "credentialFields": list(credentials), "nonemptyFields": sum(bool(x) for x in credentials.values()),
            "cacheControl": response.headers.get("Cache-Control"), "error": value.get("error")}
        assert not any(key in row for key in ["credentials", "AccessKeySecret", "token"])
    for name, args in [
        ("no-session", {"authenticated": False}),
        ("no-header", {"custom_headers": {"Origin": base}}),
        ("foreign-origin", {"custom_headers": {"X-LabProbe-Eweb": "1", "Origin": "http://example.com"}}),
        ("unknown-op", {"op": "invalid"}),
        ("bad-record-id", {"op": "ddns.credentials", "ident": "../agent.json"}),
        ("missing-revision", {"op": "wg.save"}),
        ("invalid-tcp-target", {"op": "tcp.start", "payload": {"host": ""}}),
        ("invalid-ddns-domain", {"op": "ddns.add", "payload": {"provider": "alidns", "hostname": ""}}),
    ]:
        op = args.pop("op", "wg.get")
        response, data, _ = call(op, **args)
        value = data.get("data") or {}
        proof["negative"][name] = {"status": response.status_code, "ok": value.get("ok"),
                                   "httpStatus": value.get("httpStatus"), "code": data.get("code"),
                                   "error": value.get("error")}
    folder = Path(__file__).resolve().parents[1] / "build_artifacts/oct08-eweb-hub-plan/candidate"
    for name, relative in [("hub-pages.js", "labprobe/hub-pages.js"),
                           ("hub-pages.css", "labprobe/hub-pages.css"),
                           ("app6894ab6e311358c0df7b.js", "js/app6894ab6e311358c0df7b.js")]:
        response = session.get(base + "/luci-static/eweb-ehr-exp/static/" + relative, timeout=(4, 12))
        data = response.content
        if data.startswith(b"\x1f\x8b"):
            data = gzip.decompress(data)
        proof["assets"][name] = {"status": response.status_code,
                                 "hashMatches": hashlib.sha256(data).digest() == hashlib.sha256((folder / name).read_bytes()).digest()}
    (folder.parent / "live-proof.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8")
    assert all(v.get("ok") is True for v in proof["read"].values()), "Live reads failed"
    assert proof["read"]["wg.get"]["router"] == "BE72"
    assert all(v["hashMatches"] for v in proof["assets"].values()), "Asset hash mismatch"
    assert all(v.get("ok") is not True for v in proof["negative"].values()), "An invalid operation was accepted"
    return proof
