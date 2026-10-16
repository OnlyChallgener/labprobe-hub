"""Build a reviewed patch atop the actual running HUB sources."""
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
live = root / "test_tmp_childguard_20261015" / "live_rdpi"
staged = live / "staged"
staged.mkdir(exist_ok=True)
source = (live / "hub.py").read_text(encoding="utf-8")
if hashlib.sha256(source.encode()).hexdigest() != "3e46d91b01bfd6fe0791aa28cdf13a2a0d8d29e509ae2959f10b1ef23db4e9c8":
    raise RuntimeError("Running HUB source changed; restage from the current container")
local = (root / "hub.py").read_text(encoding="utf-8")
for action, following in (
    ("add_device", '@app.route("/api/router/child-guard/devices/<uid>"'),
    ("remove_device", '@app.route("/api/router/child-guard/commands"'),
):
    original_start = f'    return _child_guard_official_membership("{action}"'
    replacement_start = ('    operation = {"macs": macs,' if action == "add_device"
                         else '    operation = {"uid": normalized_uid,')
    if source.count(original_start) != 1 or local.count(replacement_start) < 1:
        raise RuntimeError(f"Unexpected child guard route state: {action} "
                           f"old={source.count(original_start)} new={local.count(replacement_start)}")
    old_at = source.index(original_start)
    old_end = source.index(following, old_at)
    local_scope = (local.index('def api_child_guard_device_delete')
                   if action == "remove_device" else local.index('def api_child_guard_devices_collection'))
    new_at = local.index(replacement_start, local_scope)
    new_end = local.index(following, new_at)
    source = source[:old_at] + local[new_at:new_end] + source[old_end:]
start = local.index('@app.route("/api/router/rdpi/signatures/haokan"')
end = local.index('@app.route("/api/router/child-guard/ip6-audit/sync"', start)
route = local[start:end]
anchor = '@app.route("/api/router/child-guard/ip6-audit/sync"'
if source.count(anchor) != 1 or 'api_router_rdpi_signatures_haokan' in source:
    raise RuntimeError("Unexpected RDPI route state")
source = source.replace(anchor, route + anchor)
compile(source, "hub.py", "exec")
(staged / "hub.py").write_text(source, encoding="utf-8")
service = (root / "rdpi_signature_service.py").read_text(encoding="utf-8")
compile(service, "rdpi_signature_service.py", "exec")
(staged / "rdpi_signature_service.py").write_text(service, encoding="utf-8")
print("staged:", *(f"{name} {hashlib.sha256((staged/name).read_bytes()).hexdigest()}"
                    for name in ("hub.py", "rdpi_signature_service.py")))
