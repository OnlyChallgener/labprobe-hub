-- Run with the firmware Lua/json runtime. Dependencies are mocked in this
-- separate process; no real network call, configuration write or service change.
local json = require "luci.json"
local now, files, replies, calls, writes = 1000, {}, {}, {}, {}
local config = {routerName="BE72", hubUrl="http://192.168.5.46:58443"}
files["/etc/labprobe/agent.json"] = json.encode(config)
files["/etc/labprobe/eweb-hub.json"] = json.encode(config)
files["/sys/class/net/labwg0/flags"] = "1"
files["/sys/class/net/labwg0/statistics/rx_bytes"] = "100"
files["/sys/class/net/labwg0/statistics/tx_bytes"] = "200"
local fs = {readfile=function(path) return files[path] end,
    remove=function(path) files[path]=nil; return true end,
    rename=function(from, to) files[to]=files[from]; files[from]=nil; return true end}
package.loaded["nixio.fs"] = fs
package.loaded["nixio"] = {open=function(path, mode, permission)
    assert(permission=="600", "temporary cache must be private")
    return {writeall=function(_, value) files[path]=value; writes[#writes+1]=path end, close=function() end}
end}
package.loaded["luci.http"] = {getenv=function(key)
    return ({REQUEST_METHOD="POST", HTTP_X_LABPROBE_EWEB="1", HTTP_ORIGIN="http://router", HTTP_HOST="router"})[key]
end}
local helper = {ok=true, name="labwg0", peers={{publicKey="test-public-key", latestHandshakeAt=990, rxBytes=10, txBytes=20}}, latestHandshakeAt=990}
package.loaded["luci.sys"] = {exec=function(command)
    if command:find("labprobe%-wg%-status") then return json.encode(helper) end
    assert(command:find("/usr/bin/curl", 1, true))
    calls[#calls+1]=command
    assert(#replies>0, "unexpected network request")
    return table.remove(replies, 1)
end}
os.time=function() return now end
local temporary_index=0
os.tmpname=function() temporary_index=temporary_index+1; return "/mock/private-"..temporary_index end
assert(loadfile(arg[1]))()
local bridge = package.loaded["luci.modules.labprobe"]
local cache_path = "/tmp/labprobe-eweb-wg-read.json"
local good = {ok=true, revision=7, server={interfaceName="labwg0", peers={{publicKey="test-public-key", name="phone"}}}}
local function reply(value, code) return json.encode(value).."\n"..tostring(code or 200) end

replies={reply(good)}
local first=bridge.request({op="wg.get"})
assert(first.ok and first.localWireguard.peerStatusAvailable)
assert(files[cache_path] and not first.hubReadStale)
local saved=files[cache_path]

now=1005; replies={"\n000", "\n000"}; calls={}
local fallback=bridge.request({op="wg.get"})
assert(#calls==2 and calls[2]:find("--max-time 2 ",1,true))
assert(fallback.ok and fallback.hubReadStale and fallback.hubConfigEpoch==1000)
assert(fallback.localWireguard.receivedEpoch==1005 and fallback.localWireguard.peerStatusAvailable)
assert(files[cache_path]==saved, "failed reads must not refresh the metadata cache age")

replies={reply({ok=false,error="unauthorized"},401)}; calls={}
local unauthorized=bridge.request({op="wg.get"})
assert(not unauthorized.ok and unauthorized.httpStatus==401 and #calls==1)

now=1121; replies={"\n000", "\n000"}
assert(not bridge.request({op="wg.get"}).ok, "expired data cannot masquerade as current config")

now=1005
local foreign=json.decode(saved); foreign.routerName="BE50"; files[cache_path]=json.encode(foreign)
replies={"\n000", "\n000"}
assert(not bridge.request({op="wg.get"}).ok, "another router's cache is never reusable")
files[cache_path]=saved

replies={reply(good)}; calls={}
local mutation=bridge.request({op="wg.save", payload={expectedRevision=7}})
assert(mutation.ok and #calls==1 and not files[cache_path], "successful mutations invalidate the read cache and are never replayed")

print("6 bridge failure/recovery cases passed; mock network and private RAM caches only")
