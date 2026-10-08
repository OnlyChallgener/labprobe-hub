"""Build a hash-locked eWeb menu/API extension without rebuilding the firmware."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from urllib.parse import quote
from pathlib import Path

APP_NAME = "app6894ab6e311358c0df7b.js"
APP_HASH = "a4623980f36bf95e300389a90b404d06ab87cbffe6c6251cb03ee566ba475a5a"
VERSION = "20261008-5"
STATIC = "/luci-static/eweb-ehr-exp/static/labprobe/"
MARKER = "labprobe-eweb-hub-" + VERSION

def replace_once(data: bytes, anchor: bytes, value: bytes) -> bytes:
    if data.count(anchor) != 1:
        raise ValueError(f"Expected one anchor: {anchor[:90]!r}")
    return data.replace(anchor, value, 1)

def patch_app(data: bytes) -> bytes:
    if hashlib.sha256(data).hexdigest() != APP_HASH:
        raise ValueError("Unknown eWeb app revision; refuse to patch")
    # Insert the last More category after storage. No capability filters or other
    # menu entries are changed. Labels bypass missing native translation keys.
    anchor = b'],id:"1.1.13",fullPath:["admin","alone","store"]}'
    # Storage has no children: actual anchor includes children:[] before its id.
    anchor = b'children:[],id:"1.1.13",fullPath:["admin","alone","store"]}'
    loader = """
function(kind){return function(){
  if(!window.LabProbeEwebLoad)window.LabProbeEwebLoad=new Promise(function(resolve,reject){
    var css=document.createElement('link');css.rel='stylesheet';css.href='%shub-pages.css?v=%s';document.head.appendChild(css);
    var js=document.createElement('script');js.src='%shub-pages.js?v=%s';
    js.onload=function(){resolve()};js.onerror=function(){window.LabProbeEwebLoad=null;css.remove();js.remove();reject(new Error('HUB page unavailable'))};document.head.appendChild(js);
  });
  return Promise.all([n.e(0),n.e(2),window.LabProbeEwebLoad]).then(function(){return window.LabProbeEweb.createComponent(kind,n('OYeX'))});
}}
""" % (STATIC, VERSION, STATIC, VERSION)
    loader = "".join(line.strip() for line in loader.splitlines())
    children = []
    for index, (path, kind, label) in enumerate([
        ("wireguard", "wireguard", "WireGuard"), ("tcp_peak", "tcp", "TCP 峰值测试"), ("ddns", "ddns", "DDNS")], 1):
        row = json.dumps({"label": label, "path": path, "children": [], "id": f"1.1.14.{index}", "fullPath": ["admin", "alone", "hub", path]}, ensure_ascii=True)
        row = row[:-1] + ',"compPath":(' + loader + ')(' + json.dumps(kind) + ')}'
        children.append(row)
    item = '{label:"HUB",icon:"labprobe-hub-icon",path:"hub",showChilds:true,children:[' + ','.join(children) + '],id:"1.1.14",fullPath:["admin","alone","hub"]}'
    data = replace_once(data, anchor, anchor + b"," + item.encode("ascii"))
    # A rounded outline topology icon inherits the native hover/selected color.
    svg = (Path(__file__).resolve().parents[1] / "eweb/hub-icon.svg").read_text(encoding="utf-8")
    uri = "data:image/svg+xml," + quote("".join(line.strip() for line in svg.splitlines()), safe="")
    icon_css = ('.labprobe-hub-icon{display:inline-block;width:1em;height:1em;vertical-align:middle;'
                'background:currentColor;-webkit-mask:url("' + uri + '") center/contain no-repeat;'
                'mask:url("' + uri + '") center/contain no-repeat;}')
    initialize = '/*' + MARKER + '*/var labprobeIconStyle=document.createElement("style");labprobeIconStyle.textContent=' + json.dumps(icon_css) + ';document.head.appendChild(labprobeIconStyle);'
    anchor = b'var i=function(){return Promise.all([n.e(0),n.e(13)]).then(n.bind(null,"OH6J"))},r=['
    return replace_once(data, anchor, initialize.encode("ascii") + anchor)

def patch_api(data: bytes) -> bytes:
    route = b'    entry({"api", "common"}, call("rpc_common"), nil)'
    data = replace_once(data, route, route + b'\n    entry({"api", "labprobe"}, call("rpc_labprobe"), nil)')
    return data + '''
-- labprobe-eweb-hub: authentication inherited from the native API node.
function rpc_labprobe()
    local http = require "luci.http"
    if tonumber(http.getenv("CONTENT_LENGTH") or http.getenv("HTTP_CONTENT_LENGTH") or 0) > 32768 then
        http.status(413, "Payload Too Large")
        http.write_json({code=1, msg="request too large"})
        return
    end
    local jsonrpc = require "luci.utils.jsonrpc"
    local ltn12 = require "luci.ltn12"
    local bridge = require "luci.modules.labprobe"
    http.prepare_content("application/json")
    http.header("Cache-Control", "no-store")
    -- Native jsonrpc logs parameters on an uncaught exception. Keep credentials
    -- out of that path even if a filesystem/curl failure raises unexpectedly.
    local function safe_request(params)
        local ok, result = pcall(bridge.request, params)
        if ok then return result end
        return {ok=false, error="HUB 操作暂时失败，请重试", httpStatus=500}
    end
    ltn12.pump.all(jsonrpc.handle({request=safe_request}, http.source()), http.write)
end
'''.encode("utf-8")

def build(source: Path, output: Path, wg_status: Path | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    files = {APP_NAME: patch_app((source / APP_NAME).read_bytes()),
             "api.lua": patch_api((source / "router-source/api.lua").read_bytes()),
             "labprobe.lua": (root / "eweb/labprobe.lua").read_bytes(),
             "hub-pages.js": (root / "eweb/hub-pages.js").read_bytes(),
             "hub-pages.css": (root / "eweb/hub-pages.css").read_bytes()}
    if wg_status is not None:
        helper = wg_status.read_bytes()
        # A static AArch64 ELF; reject a host executable accidentally selected.
        if helper[:4] != b'\x7fELF' or int.from_bytes(helper[18:20], 'little') != 183:
            raise ValueError('Expected AArch64 WireGuard status helper')
        files['labprobe-wg-status'] = helper
    for name, content in list(files.items()):
        if name.endswith((".js", ".css")):
            files[name + ".gz"] = gzip.compress(content, mtime=0)
    for name, content in files.items():
        (output / name).write_bytes(content)
    manifest = {"version": VERSION, "files": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--wg-status", type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.output, args.wg_status), indent=2))
