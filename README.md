<p align="center">
  <img width="900" alt="WGKeeper logo" src="https://github.com/user-attachments/assets/0e8e4b9b-eec4-4b95-b48b-16455b79f732" />
</p>

<h1 align="center">WGKeeper Node</h1>

<p align="center"><strong>A WireGuard node you manage over a REST API.</strong></p>

[![CI](https://github.com/wgkeeper/wgkeeper-node/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/wgkeeper/wgkeeper-node/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://github.com/wgkeeper/wgkeeper-node/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/wgkeeper/wgkeeper-node)](https://github.com/wgkeeper/wgkeeper-node/releases/latest)
[![Image Pulls](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fghcr-badge.elias.eu.org%2Fapi%2Fwgkeeper%2Fwgkeeper-node%2Fnode&query=%24.downloadCount&label=image%20pulls&color=blue)](https://github.com/wgkeeper/wgkeeper-node/pkgs/container/node)
[![codecov](https://codecov.io/gh/wgkeeper/wgkeeper-node/graph/badge.svg)](https://codecov.io/gh/wgkeeper/wgkeeper-node)
[![Go Reference](https://pkg.go.dev/badge/github.com/wgkeeper/wgkeeper-node.svg)](https://pkg.go.dev/github.com/wgkeeper/wgkeeper-node)
[![Go](https://img.shields.io/github/go-mod/go-version/wgkeeper/wgkeeper-node)](https://github.com/wgkeeper/wgkeeper-node/blob/main/go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/wgkeeper/wgkeeper-node/badge)](https://scorecard.dev/viewer/?uri=github.com/wgkeeper/wgkeeper-node)

---

WGKeeper Node runs one WireGuard interface on a Linux host and exposes an HTTP API to create, rotate, list and delete its peers. It has no UI and no user accounts: a single orchestrator holds the API key and manages many nodes. That orchestrator can be your own service or [WGKeeper Console](https://github.com/wgkeeper/wgkeeper-console).

- Peers are created with an expiry or as permanent; expired peers are removed by the node itself.
- Keys can be rotated without changing the peer's IP address.
- IPv4, IPv6 or dual-stack, with NAT rules set up for you.
- Peer state can be persisted to a local bbolt file and is reconciled with the device on startup.
- API key auth, optional IP allowlist, rate and body limits, optional TLS.
- Optional Prometheus metrics on a separate port with its own token.

Full documentation: [wgkeeper.github.io/docs/node](https://wgkeeper.github.io/docs/node/installation).

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [API reference](#api-reference)
- [Peer store persistence](#peer-store-persistence)
- [Metrics](#metrics)
- [Security](#security)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## How it works

```mermaid
flowchart LR
  Orchestrator[Orchestrator] -->|REST API<br/>TCP 51821| API
  Clients[VPN clients] -->|WireGuard<br/>UDP 51820| WG

  subgraph Node[WGKeeper Node]
    API[REST API]
    WG[WireGuard interface]
  end

  WG --> WAN[(WAN / Internet)]
```

On startup the node writes `/etc/wireguard/<interface>.conf` if it does not exist (`./wireguard/<interface>.conf` when not running as root). In the Docker image, `entrypoint.sh` then brings the interface up with `wg-quick` and starts the API. From then on, every peer change goes through the API.

## Quick start

The fastest way to try the node is the image from GHCR with the local Compose file. Run this on a Linux host with WireGuard support.

1. Get the Compose file and the example config:

   ```bash
   git clone https://github.com/wgkeeper/wgkeeper-node.git && cd wgkeeper-node
   cp config.example.yaml config.yaml
   ```

2. Edit `config.yaml`: set `auth.api_key` to a random value (`openssl rand -hex 32`) and `wireguard.routing.wan_interface` to the host's outbound interface (`ip route show default`).

3. Start the node:

   ```bash
   docker compose -f docker-compose.local.yml up -d
   curl http://localhost:51821/healthz
   ```

4. Create a peer:

   ```bash
   curl -X POST http://localhost:51821/peers \
     -H "X-API-Key: <your api key>" \
     -H "Content-Type: application/json" \
     -d "{\"peerId\": \"$(cat /proc/sys/kernel/random/uuid)\"}"
   ```

   The response has the server's public key and port, and the peer's keys and IP addresses: everything a client config needs. The peer's private key is returned only here and is not stored.

WireGuard listens on `51820/udp`. The API listens on `51821` over plain HTTP until you configure TLS; for anything beyond a test, use the [production setup with Caddy](#docker-compose-with-caddy-production).

## Requirements

| | Requirement |
|---|-------------|
| Host | Linux with WireGuard kernel support; root or `CAP_NET_ADMIN` |
| Docker | Capabilities `NET_ADMIN` and `SYS_MODULE` |
| Bare metal | `wireguard-tools`, `iproute2`, `iptables` |

## Configuration

The node reads `./config.yaml`. Set `NODE_CONFIG` to use another path:

```bash
NODE_CONFIG=/etc/wgkeeper/config.yaml
```

`DEBUG=true` (or `1`) turns on verbose logs and puts internal error details into API responses. Do not use it in production.

See [`config.example.yaml`](config.example.yaml) for a commented example.

### Server

| Setting | Description |
|---------|-------------|
| `server.port` | API port; HTTP, or HTTPS when TLS is configured |
| `server.tls_cert` | Path to the TLS certificate (PEM); set together with `tls_key` |
| `server.tls_key` | Path to the TLS private key (PEM); set together with `tls_cert` |
| `server.allowed_ips` | Optional IPv4/IPv6 addresses or CIDRs. When set, only these clients can call protected endpoints. Behind a reverse proxy on another host or container, also set `trusted_proxies` |
| `server.trusted_proxies` | Optional addresses or CIDRs of reverse proxies allowed to set `X-Forwarded-For`. Empty means only loopback is trusted |
| `auth.api_key` | API key for all protected endpoints |

### WireGuard

| Setting | Description |
|---------|-------------|
| `wireguard.interface` | Interface name, for example `wg0` |
| `wireguard.listen_port` | WireGuard UDP port |
| `wireguard.subnet` | IPv4 CIDR for peer addresses, prefix up to `/30`. At least one of `subnet` and `subnet6` is required |
| `wireguard.server_ip` | Optional IPv4 address of the server inside `subnet` |
| `wireguard.subnet6` | IPv6 CIDR for peer addresses, prefix up to `/126` |
| `wireguard.server_ip6` | Optional IPv6 address of the server inside `subnet6` |
| `wireguard.routing.wan_interface` | Outbound interface used in the NAT rules, for example `eth0`. Letters, digits, `-`, `_` and `.` only |
| `wireguard.peer_store_file` | Optional path to a bbolt file for [persistent peers](#peer-store-persistence) |

Metrics settings are described in [Metrics](#metrics).

## Deployment

### Docker Compose (local)

[`docker-compose.local.yml`](docker-compose.local.yml) runs `ghcr.io/wgkeeper/node` with `NET_ADMIN` and `SYS_MODULE`, mounts `config.yaml` and `./wireguard`, publishes `51820/udp` and `51821`, and sets the IPv4/IPv6 forwarding sysctls on an IPv6-capable network. Use the `edge` tag for the latest build from `main`.

```bash
cp config.example.yaml config.yaml
docker compose -f docker-compose.local.yml up -d
```

For HTTPS, put the certificate and key in `./certs/` and set `server.tls_cert` and `server.tls_key`. If you don't use TLS, you can remove the `./certs:/app/certs:ro` volume.

### Docker Compose with Caddy (production)

[`docker-compose.prod-secure.yml`](docker-compose.prod-secure.yml) does not publish the API port on the host. [Caddy](https://caddyserver.com) is the only HTTP(S) entry point and proxies to the node over the Docker network.

| Service | Host ports | Internal |
|---------|-----------|----------|
| `wireguard` | `51820/udp` | API on `51821`, Docker network only |
| `caddy` | `80`, `443` | Proxies to `wireguard:51821` |

```bash
docker compose -f docker-compose.prod-secure.yml up -d
```

Example `Caddyfile`:

```Caddyfile
# Replace :443 with your domain for automatic HTTPS
:443 {
    encode gzip zstd
    reverse_proxy wireguard:51821
}
```

For production:

- Use a long random `auth.api_key`.
- Allow ports `80` and `443` in the firewall only from your orchestrator. In this setup that is the main network control.
- Point a domain at the node (for example `api.example.com`) and put it in the `Caddyfile` instead of `:443`. Caddy gets a Let's Encrypt certificate when ports 80 and 443 are reachable.
- If you change `server.port`, change `reverse_proxy wireguard:<port>` to match.
- If you use `server.allowed_ips`, also set `server.trusted_proxies` to the Docker bridge subnet. Caddy reaches the node from its own container, so without it the node compares Caddy's address, not your orchestrator's, against the allowlist and rejects every request:

  ```yaml
  server:
    allowed_ips:
      - "203.0.113.7"        # your orchestrator
    trusted_proxies:
      - "172.18.0.0/16"      # Docker bridge where Caddy runs (networks: in the compose file)
  ```

### From source

Requires Go (see `go.mod`) and the bare-metal packages from [Requirements](#requirements).

```bash
cp config.example.yaml config.yaml
go run ./cmd/server
```

| Command | Description |
|---------|-------------|
| *(no arguments)* | Start the API server |
| `init` | Create the WireGuard config if it is missing, then exit |
| `init --print-path` | Same as `init`, and print the config path to stdout |

## API reference

Protected endpoints require the `X-API-Key` header. Every response has an `X-Request-Id` header (UUID v4). Errors are JSON: `{"error": "<message>", "code": "<code>"}`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/healthz` | public | Liveness: the process is up |
| `GET` | `/readyz` | public | Readiness: the WireGuard device is available |
| `GET` | `/stats` | required | Interface statistics |
| `GET` | `/peers` | required | List peers, paginated |
| `GET` | `/peers/:peerId` | required | One peer with traffic counters |
| `POST` | `/peers` | required | Create a peer or rotate its keys |
| `DELETE` | `/peers/:peerId` | required | Delete a peer |

### GET /stats

Node and interface details: interface name, listen port, subnets, server IPs, address families, and peer counts (possible, issued, active).

### GET /peers

A page of peers in `data`, with pagination in `meta`. Each peer has `peerId`, `publicKey`, `allowedIPs`, `addressFamilies`, `active`, `lastHandshakeAt`, `createdAt` and `expiresAt`.

| Query parameter | Default | Description |
|-------|---------|-------------|
| `offset` | `0` | Number of peers to skip, `0` or more |
| `limit` | `100` | Page size, from `1` to `1000` |

Invalid values return `400`.

### POST /peers

Creates a peer. If a peer with this `peerId` exists, its keys are rotated and its IP addresses stay the same, so firewall rules that reference them keep working.

| Field | Required | Description |
|-------|----------|-------------|
| `peerId` | yes | UUID v4 chosen by the orchestrator |
| `expiresAt` | no | RFC 3339 time after which the node removes the peer. Omit for a permanent peer |
| `addressFamilies` | no | `["IPv4"]`, `["IPv6"]` or `["IPv4", "IPv6"]`. Omit to get every family the node has a subnet for |

The response has `server` (`publicKey`, `listenPort`) and `peer` (`peerId`, `publicKey`, `privateKey`, `presharedKey`, `allowedIPs`, `addressFamilies`). The node does not store the private key, so this is the only time it is returned.

Returns `409` when the subnet has no free addresses.

### GET /peers/:peerId

The same fields as in the list, plus `receiveBytes` and `transmitBytes` from the kernel. Returns `404` if the peer does not exist.

### DELETE /peers/:peerId

Removes the peer from the interface and from the peer store. Returns `404` if the peer does not exist.

## Peer store persistence

By default peers live in memory and are lost on restart. To keep them, set `wireguard.peer_store_file` to a writable path, for example `/var/lib/wgkeeper/peers.db`. In Docker, use `/app/peers/peers.db` and mount `./peers:/app/peers`.

The store is the source of truth. On startup the node reconciles the device with it in both directions: peers in the store but missing on the device are added, and peers on the device whose key is not in the store are removed. This also cleans up after a crash in the middle of a write and after manual `wg set` changes: anything not created through the API is gone after a restart.

Every create, rotate and delete is written to bbolt before the device is changed. If the device change fails, the write is rolled back. If the process crashes between the two, the next startup applies the stored state to the device. Clients that already received their keys keep working after a restart.

| Event | What happens |
|-------|-----------|
| Startup, file missing | Starts with an empty store and removes all peers from the device |
| Startup, file corrupted or has duplicate `peer_id` / `public_key` | Startup fails with an error |
| Startup, file valid | Adds stored peers to the device, removes device peers that are not in the store, removes peers outside the configured subnets |
| Peer created, rotated or deleted | Written to the store first, rolled back if the device change fails |
| Host reboot or interface recreated | All stored peers are added back to the device |
| Subnet changed in config | On the next startup, peers outside the new subnets are removed from the store and the device |
| `expiresAt` reached | A background task removes the peer |

The file stores `peer_id`, `public_key`, `preshared_key`, `allowed_ips`, `created_at` and `expires_at` per peer, never private keys. It is created with mode `0600`; keep its directory closed to other users as well.

## Metrics

The node can serve Prometheus metrics at `/metrics` on a separate port. It is off by default. The endpoint requires a bearer token that is separate from the API key and is rate limited to 5 requests per second.

```yaml
metrics:
  port: 9090
  token: "<at least 32 characters, e.g. openssl rand -hex 32>"
```

Both fields are required. The token must be at least 32 characters and must differ from `auth.api_key`; otherwise the node refuses to start.

### Exported metrics

| Metric | Type | Labels | Use |
|--------|------|--------|-----|
| `wgkeeper_peers` | gauge | `state` = `possible`, `issued`, `active` | Capacity and usage |
| `wgkeeper_peer_operations_total` | counter | `op`, `result` | Throughput and error rate |
| `wgkeeper_peer_operation_duration_seconds` | histogram | `op` | Operation latency |
| `wgkeeper_persist_rollback_total` | counter | `op` | Store writes rolled back after a failed device change |
| `wgkeeper_persist_rollback_failed_total` | counter | | Rollbacks that failed, so the store and the device disagree. Alert on any increase |
| `wgkeeper_wireguard_rx_bytes_total` | counter | | Bytes received, all peers |
| `wgkeeper_wireguard_tx_bytes_total` | counter | | Bytes sent, all peers |
| `wgkeeper_wireguard_stale_peers` | gauge | | Peers without a handshake in the last 5 minutes |
| `wgkeeper_http_requests_total` | counter | `method`, `path`, `status_class` | API traffic, error rate, bursts of `401` |
| `wgkeeper_http_request_duration_seconds` | histogram | `method`, `path` | Latency per endpoint |
| `process_*`, `go_*` | | | Standard process and Go runtime metrics |

The `path` label is the route template, such as `/peers/:peerId`, so peer IDs don't create new series. Requests to unknown routes are counted as `path="unmatched"`.

A sample [`prometheus.yml`](docs/prometheus.example.yml) and a [Grafana dashboard](docs/grafana-dashboard.json) are in `docs/`.

### Per-peer metrics

`metrics.per_peer: true` adds:

| Metric | Type | Labels |
|--------|------|--------|
| `wgkeeper_peer_rx_bytes_total` | counter | `peer_id`, `allowed_ip` |
| `wgkeeper_peer_tx_bytes_total` | counter | `peer_id`, `allowed_ip` |
| `wgkeeper_peer_last_handshake_seconds` | gauge (age) | `peer_id`, `allowed_ip` |
| `wgkeeper_peers_capped` | gauge | |

`metrics.per_peer_max` (default `100`) limits the number of peers exported: the node keeps the peers with the most traffic in the current scrape interval. The rest are still available through `GET /peers/:peerId`, and `wgkeeper_peers_capped` shows how many were left out.

| Active peers | Suggested `per_peer_max` | Series | Storage for 30 days |
|--------------|----------------------------|--------------|----------------|
| under 500 | 500 | ~1,500 | ~30 MB |
| 500 to 2,000 | 200 | ~600 | ~13 MB |
| 2,000 to 10,000 | 100 (default) | ~300 | ~7 MB |
| over 10,000 | 50 | ~150 | ~3 MB |
| over 50,000 | keep `per_peer: false` and use `GET /peers/:peerId` | | |

With many nodes and thousands of peers each, consider `vmagent` with `remote_write` to VictoriaMetrics or Grafana Mimir.

### Keep the metrics port private

The metrics endpoint listens on all interfaces. Peer counts, the version and capacity tell an attacker a lot, so don't expose it to the internet even with the token:

- **Docker:** don't add `9090:9090` to `ports:`. Run Prometheus in the same Compose project and scrape `wireguard:9090` over the Docker network. `docker-compose.local.yml` has a commented-out Prometheus service for this.
- **Docker with Caddy:** same as above. If Prometheus runs elsewhere, add a separate Caddy site (for example `metrics.example.com`) with client certificate (mTLS) auth that proxies to `wireguard:9090`.
- **Bare metal:** allow `9090/tcp` in the firewall only from `127.0.0.1` or your Prometheus host.

## Security

| Mechanism | Details |
|-----------|---------|
| API key | Required on every endpoint except `/healthz` and `/readyz` (`X-API-Key`) |
| IP allowlist | `server.allowed_ips`; when set, a request must pass both the allowlist and the API key |
| Trusted proxies | Only `127.0.0.1` and `::1` may set `X-Forwarded-For` unless `server.trusted_proxies` says otherwise, so clients can't spoof their address. See [Docker Compose with Caddy](#docker-compose-with-caddy-production) |
| Rate limiting | 20 requests per second per client IP, burst 30; off when an allowlist is configured |
| Body limit | 256 KB; larger requests get `413` |
| Input validation | Peer IDs must be UUID v4; `offset` and `limit` are range-checked |
| Config validation | `wireguard.routing.wan_interface` is restricted to a safe character set because it is used in iptables rules |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, and `Strict-Transport-Security` with TLS |
| Files on disk | WireGuard config and peer store are written with mode `0600`; private keys of peers are never stored |
| Release images | Signed build provenance and an SBOM; see [SECURITY.md](SECURITY.md#verifying-images) |

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please don't open a public issue.

## Development

```bash
go test -race ./...          # all tests
go test -bench=. ./...       # benchmarks
golangci-lint run            # linters
```

Tests cover the HTTP handlers and middleware, the peer store and its persistence, the WireGuard service (peer lifecycle, IP allocation, key rotation, expiry) and config validation.

Benchmarks run on every pull request and the comparison with `main` is posted as a comment. A snapshot of the latest results is in [`docs/benchmarks.md`](docs/benchmarks.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks and the pull request flow, and [CHANGELOG.md](CHANGELOG.md) for changes in each release.

## License

[AGPL-3.0](LICENSE).

WireGuard® is a registered trademark of Jason A. Donenfeld.
