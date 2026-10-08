-- Native eWeb session authentication is inherited from controller/eweb/api.lua.
-- This bridge exposes only fixed operations for the router's own Hub.
module("luci.modules.labprobe", package.seeall)
local http = require "luci.http"
local json = require "luci.json"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local nixio = require "nixio"

local function shellquote(value)
    return "'"..tostring(value):gsub("'", "'\\''").."'"
end

local operations = {
    ["wg.get"] = {"GET", "/api/wireguard/server"},
    ["wg.save"] = {"PUT", "/api/wireguard/server"},
    ["wg.remove"] = {"DELETE", "/api/wireguard/peers/", true},
    ["stun.get"] = {"GET", "/api/stun"},
    ["tcp.get"] = {"GET", "/api/tcp-session-test"},
    ["tcp.start"] = {"POST", "/api/tcp-session-test/start"},
    ["tcp.stop"] = {"POST", "/api/tcp-session-test/stop"},
    ["ddns.get"] = {"GET", "/api/ddns"},
    ["ddns.add"] = {"POST", "/api/ddns"},
    ["ddns.save"] = {"PUT", "/api/ddns/", true},
    ["ddns.remove"] = {"DELETE", "/api/ddns/", true},
    ["ddns.update"] = {"POST", "/api/ddns/", true, "/update"},
    ["ddns.credentials"] = {"GET", "/api/ddns/", true, "/credentials"},
}
local function failure(message, status)
    return {ok=false, error=message, httpStatus=status or 400}
end
local function load(path)
    local raw = fs.readfile(path)
    if not raw then return nil end
    local ok, value = pcall(json.decode, raw)
    return ok and value or nil
end
local function revision(value)
    return type(value)=="number" and value>=0 and value==math.floor(value)
end
local function save_private_json(path, value)
    local temporary = os.tmpname()
    local file = nixio.open(temporary, "w", "600")
    if not file then return end
    file:writeall(json.encode(value)); file:close()
    if not fs.rename(temporary, path) then fs.remove(temporary) end
end
local WG_READ_CACHE = "/tmp/labprobe-eweb-wg-read.json"
local function cached_wg(config, reason)
    local cached = load(WG_READ_CACHE)
    local now = os.time()
    if type(cached)~="table" or cached.hubUrl~=config.hubUrl or cached.routerName~=config.routerName
        or type(cached.savedEpoch)~="number" or cached.savedEpoch>now or now-cached.savedEpoch>120
        or type(cached.result)~="table" or not cached.result.ok then return nil end
    cached.result.hubReadStale = true
    cached.result.hubReadError = reason
    cached.result.hubConfigEpoch = cached.savedEpoch
    return cached.result
end
local function wireguard_local_status(result)
    local name = result.server and result.server.interfaceName
    if type(name)~="string" or #name>15 or not name:match("^[%w_.-]+$") then return end
    local base = "/sys/class/net/"..name
    local flags = tonumber(fs.readfile(base.."/flags") or "")
    -- This firmware lacks the wg CLI. An applied kernel interface can still be
    -- up while Relay's CLI capability block reports no interfaces. Read the
    -- router's live interface counters and the kernel peer telemetry.
    if not flags then return end
    local rx = tonumber(fs.readfile(base.."/statistics/rx_bytes") or "")
    local tx = tonumber(fs.readfile(base.."/statistics/tx_bytes") or "")
    if not rx or not tx then return end
    local info = {name=name, rxBytes=rx, txBytes=tx}
    local status = {running=flags%2==1, receivedEpoch=os.time(), interfaces={info}, peerStatusAvailable=false}
    -- One-shot helper uses Generic Netlink directly, without restarting Relay
    -- or the WireGuard interface. Its JSON contains public fields only.
    local ok, raw = pcall(sys.exec, "/usr/libexec/labprobe-wg-status "..shellquote(name).." 2>/dev/null")
    if ok and type(raw)=="string" and #raw<=65536 then
        local parsed, peers = pcall(json.decode, raw)
        if parsed and type(peers)=="table" and peers.ok and peers.name==name and type(peers.peers)=="table" then
            local cache_path = "/tmp/labprobe-wg-activity-"..name..".json"
            local previous = load(cache_path) or {}
            local cache = {}
            for _, peer in ipairs(peers.peers) do
                if type(peer)=="table" and type(peer.publicKey)=="string" then
                    local old = previous[peer.publicKey] or {}
                    local received = tonumber(peer.rxBytes)
                    local last = tonumber(old.rxBytes)
                    local activity = tonumber(old.lastActivityAt)
                    -- Received authenticated packets prove current activity.
                    -- Sent packets and historical totals alone do not.
                    local observed = tonumber(old.observedEpoch)
                    if received and last and received>last and observed and observed<=status.receivedEpoch and status.receivedEpoch-observed<=90 then activity=status.receivedEpoch end
                    if received and last and received<last then activity=nil end
                    if activity and activity<=status.receivedEpoch then peer.lastActivityAt=activity end
                    cache[peer.publicKey] = {rxBytes=received, lastActivityAt=activity, observedEpoch=status.receivedEpoch}
                end
            end
            save_private_json(cache_path, cache)
            status.peers = peers.peers
            status.peerStatusAvailable = true
            status.latestHandshakeAt = peers.latestHandshakeAt
            info.publicKey = peers.publicKey
            info.latestHandshakeAt = peers.latestHandshakeAt
        end
    end
    result.localWireguard = status
end
function request(params)
    if http.getenv("REQUEST_METHOD") ~= "POST" or http.getenv("HTTP_X_LABPROBE_EWEB") ~= "1" then
        return failure("请从当前路由器的 HUB 页面操作", 403)
    end
    local origin, host = http.getenv("HTTP_ORIGIN"), http.getenv("HTTP_HOST")
    if origin and origin ~= "http://"..(host or "") and origin ~= "https://"..(host or "") then
        return failure("请求来源与当前路由器不一致", 403)
    end
    if type(params) ~= "table" then return failure("请求格式无效") end
    local op = operations[params.op]
    if not op then return failure("不支持此操作") end
    local path = op[2]
    if op[3] then
        if type(params.id)~="string" or #params.id>64 or not params.id:match("^[%w_-]+$") then
            return failure("记录编号无效")
        end
        path = path..params.id..(op[4] or "")
    end
    local body = params.payload or {}
    if type(body)~="table" then return failure("参数格式无效") end
    if params.op == "wg.save" or params.op == "wg.remove" then
        if not revision(body.expectedRevision) then return failure("请先读取最新配置") end
        if params.op == "wg.remove" then path=path.."?expectedRevision="..body.expectedRevision end
    end
    local config = load("/etc/labprobe/eweb-hub.json")
    local agent = load("/etc/labprobe/agent.json")
    if not config or not agent or config.routerName ~= agent.routerName or config.hubUrl ~= agent.hubUrl then
        return failure("HUB 与当前路由器的绑定不一致", 409)
    end
    if config.routerName~="BE72" or config.hubUrl~="http://192.168.5.46:58443" then
        return failure("当前路由器未启用 HUB 页面", 403)
    end
    -- Private curl config contains Authorization; it never enters argv or replies.
    local temporary = os.tmpname()
    local serialized = json.encode(body)
    if not serialized or #serialized>32768 then return failure("请求内容过长") end
    local file = nixio.open(temporary, "w", "600") -- native nixio takes octal text
    if not file then return failure("暂时无法提交请求", 500) end
    file:writeall(serialized)
    file:close()
    local timeout = params.op=="wg.get" and 4 or params.op:match("^ddns%.") and op[1]~="GET" and 30 or 8
    local command = "/usr/bin/curl --silent --max-filesize 1048576 --connect-timeout 2 --max-time "..timeout..
        " --config /etc/labprobe/eweb-hub.curl --request "..op[1]..
        " --url "..shellquote(config.hubUrl..path).." --write-out '\\n%{http_code}'"
    if op[1]~="GET" and op[1]~="DELETE" then command=command.." --data-binary @"..shellquote(temporary) end
    local function fetch(command_text)
        local success, raw = pcall(sys.exec, command_text.." 2>/dev/null")
        if not success or type(raw)~="string" or #raw>1048576 then return nil, 0 end
        local text, code = raw:match("^(.*)\n(%d%d%d)$")
        local valid, result = pcall(json.decode, text or "")
        return valid and type(result)=="table" and result or nil, tonumber(code) or 0
    end
    local result, code = fetch(command)
    -- Retry only this idempotent read; never replay a configuration mutation.
    if params.op=="wg.get" and (code==0 or code>=500 or not result and code>=200 and code<300) then
        result, code = fetch(command:gsub("%-%-max%-time 4 ", "--max-time 2 ", 1))
        if code==0 or code>=500 or not result and code>=200 and code<300 then
            local fallback = cached_wg(config, code==0 and "HUB_UNREACHABLE" or "HUB_INVALID_RESPONSE")
            if fallback then wireguard_local_status(fallback); fs.remove(temporary); return fallback end
        end
    end
    fs.remove(temporary)
    if not result or code==0 or code>=500 then return failure(code==0 and "HUB 暂时无法连接，请重试" or "HUB 暂时未返回可用数据，请重试", 502) end
    result.httpStatus = code
    if result.httpStatus==401 or result.httpStatus==403 then
        return failure("HUB 服务授权失效，请检查路由器端配置", result.httpStatus)
    end
    if params.op=="wg.get" and result.ok and code>=200 and code<300 then
        save_private_json(WG_READ_CACHE, {routerName=config.routerName, hubUrl=config.hubUrl, savedEpoch=os.time(), result=result})
        wireguard_local_status(result)
    elseif (params.op=="wg.save" or params.op=="wg.remove") and result.ok then fs.remove(WG_READ_CACHE) end
    return result
end
