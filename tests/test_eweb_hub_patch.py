import gzip
import hashlib
from pathlib import Path
import pytest
from scripts.patch_be72_eweb_hub import APP_HASH, patch_app, patch_api

SOURCE = Path('build_artifacts/oct08-eweb-hub-plan')

def test_unknown_firmware_cannot_be_patched():
    with pytest.raises(ValueError, match='Unknown'):
        patch_app(b'unknown firmware')

@pytest.mark.skipif(not SOURCE.exists(), reason='live firmware artifact not supplied')
def test_native_bundle_preserved_and_menu_is_last():
    original = (SOURCE / 'app6894ab6e311358c0df7b.js').read_bytes()
    assert hashlib.sha256(original).hexdigest() == APP_HASH
    result = patch_app(original)
    assert b'fullPath:["admin","alone","store"]},{label:"HUB"' in result
    assert b'"fullPath": ["admin", "alone", "hub", "ddns"]' in result
    assert gzip.decompress(gzip.compress(result, mtime=0)) == result
    assert result.count(b'window.LabProbeEweb.createComponent(kind') == 3

def test_bridge_inherits_authentication_and_exposes_only_request():
    fixture = b'    entry({"api", "common"}, call("rpc_common"), nil)'
    result = patch_api(fixture)
    assert b'entry({"api", "labprobe"}, call("rpc_labprobe"), nil)' in result
    assert b'{request=safe_request}' in result
    assert b'pcall(bridge.request, params)' in result
    assert b'.sysauth = false' not in result

def test_proxy_is_fixed_to_router_hub_and_uses_private_header_file():
    source = Path('eweb/labprobe.lua').read_text(encoding='utf-8')
    assert 'config.routerName ~= agent.routerName' in source
    assert 'config.hubUrl ~= agent.hubUrl' in source
    assert 'HTTP_X_LABPROBE_EWEB' in source
    assert 'HTTP_ORIGIN' in source
    assert 'config.hubUrl..path' in source
    assert 'Authorization:' not in source
    assert 'nixio.open(temporary, "w", "600")' in source
