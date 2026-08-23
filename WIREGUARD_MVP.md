# WireGuard Agent/Hub MVP

## Scope

LabProbe uses the router's existing Linux WireGuard kernel module. Agent is the
server controller; Hub stores desired public configuration and status. VPN
traffic never traverses Hub.

Agent configures the kernel through WireGuard Generic Netlink via
`wireguard-control`. It does not require the `wg` executable. The existing `ip`
binary is invoked directly (never through a shell) only to assign the tunnel
address and set the link up/down. BE72 already provides this binary and the
WireGuard kernel module.

## Security boundaries

- The server private key is generated on first apply and stored only at
  `/etc/labprobe/wireguard/private.key` with mode `0600`.
- Hub rejects `privateKey`, `presharedKey`, `secret`, and `password` recursively
  in desired configuration and Agent status.
- Hub receives only the server public key, public peer keys, counters and
  capability/status fields.
- Agent accepts a typed document. There is no arbitrary command or shell API.

## Revisions and offline convergence

`revision` covers kernel/server configuration. `endpointRevision` covers only
resolved public endpoints. Updating DDNS or STUN never causes a kernel
reconfiguration.

Each command carries the desired revision. Agent ignores an older revision and
returns its cached result for an already-applied revision. Deleting a server
stores a revisioned tombstone so an Agent that reconnects cannot recreate an
older server configuration.

App writes should include `expectedRevision`; endpoint updaters should include
`expectedEndpointRevision`. A mismatch returns HTTP 409.

## Endpoint profiles

Manual, DDNS and STUN are distinct client profiles:

- `endpointSource=manual`: immutable endpoint, no updater owner. Automatic
  endpoint commands are rejected by both Hub and Agent.
- `endpointSource=ddns`: fixed WireGuard UDP port and one hostname.
- `endpointSource=stun`: a dedicated enabled UDP STUN rule using the router's
  native port mapping to the Agent's fixed WireGuard listen port.

The STUN rule owns its NAT channel and the router-native mapping forwards that
channel to WireGuard's fixed local listen port. WireGuard must not bind to the
changing STUN channel port. Consequently, DDNS and STUN updaters cannot
overwrite the same endpoint.
Every automatic update carries `endpointSource`, the stable `owner` identity,
and `expectedEndpointRevision`. Endpoint revision is independent of the server
profile revision, so a stale DDNS/STUN result cannot overwrite a newer endpoint
or a manual value and does not reconfigure the kernel interface.

## API contract

- `GET /api/wireguard/server` — desired document plus latest Agent status.
- `PUT /api/wireguard/server` — validate/save desired state and queue apply.
- `DELETE /api/wireguard/server` — queue deletion and retain tombstone.
- `PATCH /api/wireguard/endpoints/{profileId}` — source-owned endpoint update.
- `GET /api/router/wireguard/commands` — Agent command polling.
- `POST /api/router/wireguard/ack` — idempotent command result.
- `POST /api/router/wireguard/status` — capability and applied revision.

## Remaining deployment work

- Wire the existing STUN runtime to call the source-owned endpoint updater.
- Add any remaining router eWeb port-mapping lifecycle for the fixed DDNS mode;
  its inbound firewall rule is already owned and reconciled by the Hub.
- Add routing/NAT policy for full-tunnel clients. The MVP only provisions the
  WireGuard interface, address, fixed listen port and peers.
- Validate the ARM64 artifact on BE72, including Generic Netlink permissions,
  link address assignment and reboot persistence/reconciliation.

## Capacity target

The Agent control path is idle between 5-second polls and does not handle data
packets. Expected persistent storage is one 45-byte private key plus small JSON
state. Runtime memory increase comes mostly from the embedded Netlink control
library; the kernel owns packet encryption and peer state.
