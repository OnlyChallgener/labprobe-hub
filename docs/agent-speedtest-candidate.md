# Router-local speed test candidate

This candidate performs real HTTP traffic on the router when a Hub command explicitly starts it. It is not deployed, and ships with no production nodes. A firmware speed test remains preferred when available. The Agent engine must not be selected until the Hub confirms the firmware engine is absent and the Agent advertises a configured node.

## Existing command path and candidate contract

The Agent uses the existing authenticated Hub HTTP client and local Unix control socket. Its new independent lane reads `GET /api/router/speedtest/commands?router=<router>&limit=5`, sends each command to the local daemon, then posts `{acks:[{id,ok,result}]}` to `/api/router/speedtest/ack`. It posts `{capability,status}` to `/api/router/speedtest/status`; the Hub must resolve router scope from the authenticated token, as with the existing TCP test lane.

Local commands are `speedtest_capability`, `speedtest_status`, `speedtest_start`, and `speedtest_cancel`. Start accepts `{taskId,config:{nodeId,downloadBytes,uploadBytes,phaseTimeoutSeconds}}`; cancel accepts `{taskId}`. Hub command actions are `start` and `cancel` (`stop` is also accepted). Reading capability/status never creates test traffic. Starts are idempotent for the last 32 accepted task IDs during the daemon lifetime; a second concurrent task is rejected.

`status` includes `id`, `nodeId`, `nodeName`, `engine:"agent"`, `measurement:"single_tcp_http_payload"`, `state`, `phase`, nullable `error`, `latencyMs`, `jitterMs`, `downloadMbps`, `uploadMbps`, `uploadBytes`, and timestamps. `downloadBytes` and `uploadBytesSent` are progress counters. Sent bytes do not prove successful upload. `uploadBytes` and `uploadMbps` are only populated after the server acknowledges the full upload. Unknown metrics serialize as `null`. Successful earlier phases remain visible if a later phase fails. States are `idle`, `running`, `cancel_requested`, `cancelled`, `failed`, and `completed`.

The measured rate is actual fixed-volume, single TCP HTTP payload throughput, including request setup and server acknowledgement. It does not establish a multi-stream saturation rate. Latency is the mean of three complete small HTTP exchanges, including connection/TLS setup; jitter is the mean absolute change between consecutive exchanges. These are not ICMP ping or packet loss measurements. No packet loss value is synthesized.

## Explicit HTTP node protocol

An operator must install `/etc/labprobe/speedtest-nodes.json` as a JSON array, with each node containing `id`, `name`, `protocol:"labprobe-http-v1"`, `verification`, `latencyUrl`, `downloadUrl`, and `uploadUrl`. `verification` records the authorized endpoint's provenance and protocol verification. The command channel accepts only a node ID, never endpoint URLs. Endpoint URLs must be supplied by an authorized service owner after validating the protocol below. The firmware server list currently supplies IDs/names only; those do not constitute usable HTTP endpoint evidence, so no mapping is invented.

All endpoint responses must be HTTP 200 and uncompressed (`Content-Encoding` absent or `identity`). HTTP/1.1 is used, redirects and environment proxies are disabled, URL credentials are forbidden, all resolved addresses must be public unicast, and the validated DNS results are pinned in the HTTP client. Loopback is only permitted by a private `cfg(test)` fixture flag. There is no production override for private networks.

1. Latency: GET `latencyUrl`, with `Accept-Encoding: identity` and `Cache-Control: no-store`; response body at most 4 KiB.
2. Download: GET `downloadUrl`, with the same headers plus `X-LabProbe-Bytes: N`; the server must return exactly N payload bytes. Too many/too few bytes fails the phase. The engine counts actual streamed response bytes.
3. Upload: POST `uploadUrl`, `Content-Type: application/octet-stream`, `Content-Length: N`, streaming exactly N bytes. The server must fully consume the body before replying with a JSON object containing an integer `bytesReceived` exactly equal to N. The acknowledgement body is limited to 4 KiB. The Agent must not count an arbitrary successful POST response as proof of received bytes.

An existing service using another upload acknowledgement or download query convention requires an explicit reviewed adapter and verified owner authorization. Changing only an endpoint string does not establish protocol compatibility.

BE72 read-only evidence collected on 2026-10-23 is retained at `D:/Github/ShinyaHub/test/be72-speedtest-20261023`: `speedtest.elf -n` returned ten node IDs/names without endpoint URLs. The Lua wrapper exposes an SDK option and a custom-server option, but neither proves that those native nodes support this HTTP v1 contract. No URL was recovered or verified for reuse. Common LibreSpeed `garbage.php` / `empty.php` deployments return an empty upload response rather than this candidate's `bytesReceived` acknowledgement, so they cannot be configured as compatible nodes without a separately verified adapter. The candidate intentionally retains upload verification instead of treating an early HTTP 200 response as measured throughput.

## Resource limits and verification

One active task and one active HTTP connection; idle pooling is disabled. Each phase defaults to 16 MiB and is limited to 128 MiB. Phase timeout is 1–15 seconds, connection timeout is four seconds, DNS lookup timeout is four seconds per endpoint, and the entire task is limited to 45 seconds. Cancellation drops the active future and request/response streams, retaining the single-task lock until cleanup finishes. No test body or response is accumulated as a large byte vector.

Upload application data holds one reusable 64 KiB pseudo-random block and a current block of at most 64 KiB; generation occurs before the timed upload. Download chunks are consumed immediately. HTTP/TLS/socket allocations remain additional bounded transport overhead; a measured device RSS budget cannot be claimed until an isolated ARMv7 build and on-device validation are authorized. Node configuration reads are limited to 64 KiB / 16 nodes, server acknowledgements to 4 KiB, DNS results to 16 addresses per endpoint, and retained task IDs to 32. There are no growing sample/history arrays.

`scripts/test_speedtest_engine.ps1` runs the exact production module through an isolated local Windows test harness, using the candidate lockfile versions. Its fixtures cover actual socket download/upload byte accounting, no traffic from status polling, idempotent replay, single-task exclusion, timeout, cancellation, upload acknowledgement mismatch, redirect rejection, and private-address/command-URL rejection. No public traffic is generated by these tests. The full daemon's Linux/ARM build remains a separate required gate; this machine lacks the ARM C cross-compiler, and no NAS or router deployment is performed by the script.
