# API reference

The API is plain HTTP on `server.port` (default `51821`) and takes and returns JSON. Protected endpoints require the API key in the `X-API-Key` header. Every response has an `X-Request-Id` header (UUID v4); the same ID is in the node's log for that request.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | [`/healthz`](#get-healthz) | public | Liveness: the process is up |
| `GET` | [`/readyz`](#get-readyz) | public | Readiness: the WireGuard device is available |
| `GET` | [`/stats`](#get-stats) | required | Node and interface details, peer counts |
| `GET` | [`/peers`](#get-peers) | required | List peers, paginated |
| `GET` | [`/peers/:peerId`](#get-peerspeerid) | required | One peer with traffic counters |
| `POST` | [`/peers`](#post-peers) | required | Create a peer or rotate its keys |
| `DELETE` | [`/peers/:peerId`](#delete-peerspeerid) | required | Delete a peer |

## GET /healthz

Returns `200` with `{"status": "ok"}` while the process is running.

## GET /readyz

Returns `200` with `{"status": "ok"}` when the WireGuard device can be read, and `503` with `{"status": "unhealthy", "reason": "wireguard_unavailable"}` when it can't. Use it for health checks and load balancers.

## GET /stats

```json
{
  "service": { "name": "wgkeeper-node", "version": "2.0.0" },
  "wireguard": {
    "interface": "wg0",
    "listenPort": 51820,
    "subnets": ["10.0.0.0/24"],
    "serverIps": ["10.0.0.1"],
    "addressFamilies": ["IPv4"]
  },
  "peers": { "possible": 253, "issued": 12, "active": 9 },
  "startedAt": "2026-10-31T12:00:00Z"
}
```

`peers.possible` is the number of addresses the subnets can hand out, `issued` the number of peers, and `active` the peers with a handshake in the last 2 minutes.

## GET /peers

Returns a page of peers in `data`, with pagination in `meta`.

| Query parameter | Default | Description |
|-----------------|---------|-------------|
| `offset` | `0` | Number of peers to skip, `0` or more |
| `limit` | `100` | Page size, from `1` to `1000` |

Invalid values return `400 invalid_pagination`.

```json
{
  "data": [
    {
      "peerId": "8f0c6a52-3b7e-4d4f-9a61-2f5c1d7e9b10",
      "allowedIPs": ["10.0.0.2/32"],
      "addressFamilies": ["IPv4"],
      "publicKey": "<base64>",
      "active": true,
      "lastHandshakeAt": "2026-10-31T12:04:10Z",
      "createdAt": "2026-10-30T09:15:00Z",
      "expiresAt": "2026-11-30T00:00:00Z"
    }
  ],
  "meta": {
    "offset": 0,
    "limit": 100,
    "totalItems": 1,
    "hasPrev": false,
    "hasNext": false
  }
}
```

`active` means a handshake in the last 2 minutes. `expiresAt` is left out for a permanent peer, and `lastHandshakeAt` is `null` until the first handshake. `meta.prevOffset` and `meta.nextOffset` are present when there is a previous or next page.

## GET /peers/:peerId

Returns one peer with the same fields as in the list, plus `receiveBytes` and `transmitBytes` from the kernel.

## POST /peers

Creates a peer. If a peer with this `peerId` exists, its keys are rotated and its IP addresses stay the same, so firewall rules that reference them keep working.

| Field | Required | Description |
|-------|----------|-------------|
| `peerId` | yes | UUID v4 chosen by the orchestrator |
| `expiresAt` | no | RFC 3339 time in the future after which the node removes the peer. Omit for a permanent peer; when rotating, omit to keep the current expiry |
| `addressFamilies` | no | `["IPv4"]`, `["IPv6"]` or `["IPv4", "IPv6"]`. Omit to get every family the node has a subnet for |

Unknown fields and anything after the JSON object return `400 invalid_json`, so a misspelled field such as `expires_at` can't silently create a permanent peer.

```bash
curl -X POST http://127.0.0.1:51821/peers \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"peerId": "8f0c6a52-3b7e-4d4f-9a61-2f5c1d7e9b10", "expiresAt": "2026-11-30T00:00:00Z"}'
```

```json
{
  "server": { "publicKey": "<base64>", "listenPort": 51820 },
  "peer": {
    "peerId": "8f0c6a52-3b7e-4d4f-9a61-2f5c1d7e9b10",
    "publicKey": "<base64>",
    "privateKey": "<base64>",
    "presharedKey": "<base64>",
    "allowedIPs": ["10.0.0.2/32"],
    "addressFamilies": ["IPv4"]
  }
}
```

The response has everything a client config needs. The node doesn't store the peer's private key, so this is the only time it is returned.

## DELETE /peers/:peerId

Removes the peer from the interface and from the [peer store](peer-store.md). Returns `200` with `{"status": "ok"}`.

## Errors

Errors are JSON with a message and a stable code: `{"error": "<message>", "code": "<code>"}`. Match on `code`; the message is for people and may change.

| Status | Code | When |
|--------|------|------|
| `401` | `unauthorized` | The `X-API-Key` header is missing or wrong |
| `400` | `invalid_json` | The body isn't one JSON object, or has unknown fields |
| `400` | `invalid_peer_id` | `peerId` isn't a UUID v4 |
| `400` | `invalid_expires_at` | `expiresAt` isn't RFC 3339 or isn't in the future |
| `400` | `invalid_address_family` | `addressFamilies` has an unknown or repeated value |
| `400` | `unsupported_address_family` | The node has no subnet for a requested family |
| `400` | `invalid_pagination` | `offset` or `limit` is out of range |
| `404` | `peer_not_found` | No peer with this `peerId` |
| `409` | `no_available_ip` | The subnet has no free addresses |
| `409` | `peer_expired` | Rotating a peer whose expiry has passed, without a new future `expiresAt` |
| `413` | `body_too_large` | The body is over 256 KB |
| `503` | `device_timeout` | The WireGuard device didn't respond in time. The change is stored and reaches the device when it recovers; retrying is safe |
| `503` | `device_busy` | An earlier device call is still stuck. Nothing was changed; retry later |
| `500` | `wireguard_error`, `stats_unavailable`, `peers_list_unavailable`, `server_info_unavailable`, `internal_error` | Unexpected failure. The details are in the node's log under the request ID |
