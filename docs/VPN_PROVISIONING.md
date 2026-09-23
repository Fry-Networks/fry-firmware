# WireGuard provisioning

How a board gets a WireGuard peer without anyone typing keys into it. This documents a
hardwareapi-side addition; it is not part of `PROTOCOL.md`'s shared device protocol and is not a
contract with the Android app.

## Why this exists

The firmware has shipped a WireGuard client for a while, but nothing ever populated its
configuration except a lab-only serial command (`set_wg`, gated behind `FRY_SERIAL_PROVISION` and
never compiled into a release build). A field board's tunnel simply never came up. This adds a
fetch path: once a board has registered and holds its own device token, it generates a keypair on
first boot, sends the public half to the server, and stores whatever comes back.

## Request

```
POST /vpn/v1/wireguard/{miner_key}/peer
Authorization: Bearer <device token>
Content-Type: application/json

{"public_key":"<44-char base64>","firmware_version":"<version>","chip":"<chip>"}
```

The private key is generated on the device with the hardware RNG, clamped per RFC 7748, and never
leaves it. Only the per-device token issued at registration is accepted — a board with no token
yet, or one still on a shared/bootstrap token, gets nothing.

## Response (2xx)

```
{
  "server": {"public_key": "...", "endpoint_host": "...", "endpoint_port": 51820},
  "peer": {
    "tunnel_address": "<cidr>",
    "allowed_ips": ["<cidr>", ...],
    "preshared_key": "..." | null,
    "persistent_keepalive": 25
  }
}
```

`allowed_ips` is capped at 8 entries server-side. The firmware plans routes from it (see below)
rather than trusting it verbatim.

## Route planning

`droscy/esp_wireguard`'s `WIREGUARD_MAX_SRC_IPS` build-time constant defaults to 1, and that one
slot is always filled with the device's own tunnel address. Left alone, a peer can never express a
route back to the server's own tunnel IP: the handshake completes but no data ever crosses. This
firmware raises the constant to 4 and plans up to 3 additional routes from the server's
`allowed_ips`, with a few defensive rules:

- anything wider than a `/8` is dropped (no default-route peers);
- duplicates collapse to one entry;
- if the plan would otherwise route the board's own Wi-Fi address or gateway through the tunnel,
  that candidate is narrowed until it no longer does, rather than accepted as-is;
- if nothing survives, the plan falls back to the tunnel's own subnet, so a peer is never left
  with zero routes.

## Retry / backoff

The fetch runs on its own schedule, never a tight loop, classified by outcome:

| Outcome | Delay |
|---|---|
| No device token yet / heap gate not clear | 60 s |
| Clock not synced yet | 5 min |
| Transport error / 5xx | 30 s, doubling each attempt, capped at 30 min |
| 401 (bad/expired token) | 15 min |
| 403 (`provisioning_not_open`, or any other scope rejection) | 6 h — deliberately long, since a board that isn't allow-listed will see this every time it tries |
| 409 / 429 | honours a `Retry-After` value if the server sends one (clamped to 1 min–24 h), else 1 h |
| Any other 4xx | 6 h |

A 403 in particular is expected and harmless for a board that hasn't been opened up server-side
yet: it means "keep doing everything else, just not this," and telemetry/registration keep running
on their own cadence regardless.

## NVS keys touched (`fry_vpn` namespace)

`wgPriv`, `wgPub` — this device's own keypair, generated once and never regenerated.
`wgPeerPub`, `wgPsk`, `wgEndpoint`, `wgPort`, `wgAddr`, `wgAllowed`, `wgKeepalive` — what the
server returned, plus the planned routes. `wgProvAt` — the epoch second of the last successful
provisioning POST; 0 means never provisioned. A production build only brings the tunnel up once
this is non-zero, so an unprovisioned board's dormant WireGuard client never tries to run with a
missing or half-written configuration.

## What this is not

This does not open the tunnel to anything by itself — that is a server-side allow-list decision,
made per device, independent of the firmware. It also does not change how a board is registered,
claimed, or gets its wallet attached; all of that is unchanged.
