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
- Peers are stored in a local bbolt file and restored on the interface after every restart.
- Peers get internet access only: they can't reach each other, the node itself, cloud metadata or private networks unless you allow it.
- A small HTTP API with API key auth. HTTPS, IP filtering and rate limits are left to the reverse proxy you already use (Caddy, nginx, anything else); a ready Caddy setup and an nginx example are included.
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

On every start the node writes `/etc/wireguard/<interface>.conf` (`./wireguard/<interface>.conf` when not running as root) from `config.yaml`: addresses, listen port and NAT rules. The server private key is generated on the first start and kept in that file afterwards, so the server's public key never changes. Don't edit the file by hand; change `config.yaml` instead. In the Docker image, `entrypoint.sh` then brings the interface up with `wg-quick` and starts the API. From then on, every peer change goes through the API.

## Quick start

The fastest way to try the node is the image from GHCR with the local Compose file. Run this on a Linux host with WireGuard support.

1. Get the Compose file and the example config:

   ```bash
   git clone https://github.com/wgkeeper/wgkeeper-node.git && cd wgkeeper-node
   cp config.example.yaml config.yaml
   ```

2. Edit `config.yaml`: set `auth.api_key` to a random value (`openssl rand -hex 32`). The outbound interface for NAT is detected from the default route.

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

WireGuard listens on `51820/udp`. The API is plain HTTP on `51821`, published on `127.0.0.1` only. To reach it from other machines, use the [production setup with Caddy](#docker-compose-with-caddy-production).

## Requirements

| | Requirement |
|---|-------------|
| Host | Linux with WireGuard kernel support; root or `CAP_NET_ADMIN` |
| Docker | Capability `NET_ADMIN`. On kernels older than 5.6, load the module on the host (`modprobe wireguard`) instead of granting `SYS_MODULE` |
| Bare metal | `wireguard-tools`, `iproute2`, `iptables` |

## Configuration

The node reads `./config.yaml`. Set `NODE_CONFIG` to use another path:

```bash
NODE_CONFIG=/etc/wgkeeper/config.yaml
```

`DEBUG=true` (or `1`) turns on debug-level logs. API responses are the same either way: internal error details are only ever written to the log, next to the request's `X-Request-Id`.

See [`config.example.yaml`](config.example.yaml) for a commented example. Everything except the API key and a subnet has a default, so the smallest working config is:

```yaml
auth:
  api_key: "<at least 32 characters>"
wireguard:
  subnet: "10.0.0.0/24"
```

Unknown keys are errors, so a misspelled key stops the node instead of silently being ignored.

### Server

| Setting | Description |
|---------|-------------|
| `server.port` | API port, default `51821`. The API is plain HTTP; see [Deployment](#deployment) for HTTPS |
| `auth.api_key` | API key for all protected endpoints, at least 32 characters |

The node has no TLS, IP allowlist or rate limit settings. Put those in the reverse proxy in front of it, where they are easier to configure and to change. `server.tls_cert`, `server.tls_key`, `server.allowed_ips` and `server.trusted_proxies` were removed in 1.4.0; the node refuses to start if the config still has them, so a setup that relied on them is never silently left unprotected.

### WireGuard

| Setting | Description |
|---------|-------------|
| `wireguard.interface` | Interface name, default `wg0`. Up to 15 letters, digits, `-`, `_` and `.` |
| `wireguard.listen_port` | WireGuard UDP port, default `51820` |
| `wireguard.subnet` | IPv4 CIDR for peer addresses, prefix up to `/30`. At least one of `subnet` and `subnet6` is required |
| `wireguard.server_ip` | Optional IPv4 address of the server inside `subnet` |
| `wireguard.subnet6` | IPv6 CIDR for peer addresses, prefix up to `/126` |
| `wireguard.server_ip6` | Optional IPv6 address of the server inside `subnet6` |
| `wireguard.routing.wan_interface` | Optional outbound interface for the NAT rules, for example `eth0`. When unset, the interface of the default route is used (IPv4 first, then IPv6). Set it for policy routing or when the default route is not the way out. Letters, digits, `-`, `_` and `.` only |
| `wireguard.routing.allow_private_networks` | Let peers reach private and shared address space through the node (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`), for example an office LAN. Default `false`. See [Peer isolation](#peer-isolation) |
| `wireguard.peer_store_file` | Optional path of the [peer store](#peer-store-persistence). Default `/var/lib/wgkeeper/peers.db` |

Metrics settings are described in [Metrics](#metrics).

## Deployment

### Docker Compose (local)

[`docker-compose.local.yml`](docker-compose.local.yml) runs `ghcr.io/wgkeeper/node` with `NET_ADMIN` and `no-new-privileges`, mounts `config.yaml`, `./wireguard` and `./data`, publishes `51820/udp` on all interfaces and the API on `127.0.0.1:51821` only, and sets the IPv4/IPv6 forwarding sysctls on an IPv6-capable network. Use the `edge` tag for the latest build from `main`.

```bash
cp config.example.yaml config.yaml
docker compose -f docker-compose.local.yml up -d
```

This setup is for trying the node on the same machine. For access from another host, use the Caddy setup below.

### Docker Compose with Caddy (production)

[`docker-compose.prod-secure.yml`](docker-compose.prod-secure.yml) puts [Caddy](https://caddyserver.com) in front of the node. Caddy reaches the API over the Docker network at `wireguard:51821` and is the only HTTP(S) entry point. The API port is never published.

| Published port | Served by |
|----------------|-----------|
| `51820/udp` | WireGuard |
| `80`, `443` | Caddy: HTTPS with an automatic Let's Encrypt certificate, proxied to the API |

```bash
docker compose -f docker-compose.prod-secure.yml up -d
```

Edit the [`Caddyfile`](Caddyfile) before starting:

```Caddyfile
api.example.com {
    encode gzip zstd

    # Optional: allow only your orchestrator
    # @blocked not remote_ip 203.0.113.7
    # abort @blocked

    reverse_proxy wireguard:51821
}
```

For production:

- Use a long random `auth.api_key`.
- Replace `api.example.com` with a domain pointing at the node. Caddy gets the certificate once ports 80 and 443 are reachable.
- Allow ports `80` and `443` in the firewall only from your orchestrator, or uncomment the `remote_ip` block above. Caddy sees the real client address, so no extra node settings are needed.
- If you change `server.port`, change `reverse_proxy wireguard:<port>` and the port in the healthcheck to match.

### Using another reverse proxy

Nothing in the node depends on Caddy. nginx, Traefik, HAProxy or a cloud load balancer work the same way, as long as the proxy:

1. Terminates TLS. The node only speaks HTTP. Send HSTS from the proxy.
2. Forwards to `<node>:<server.port>` over loopback or a private network. Never publish the node's port on a public interface.
3. Filters clients by IP and rate-limits, if you need either. The node does neither.
4. Sets `X-Forwarded-For` to the client address, overwriting any value the client sent. The node logs it as `forwarded_for` next to the TCP peer address; nothing in the node trusts it for access.
5. Allows at least 30s per request and bodies up to 256 KB.
6. Doesn't route `/metrics` or the metrics port through the public site.

[`examples/nginx/nginx.conf`](examples/nginx/nginx.conf) is a complete nginx example.

### From source

Requires Go (see `go.mod`) and the bare-metal packages from [Requirements](#requirements).

```bash
cp config.example.yaml config.yaml
go run ./cmd/server
```

| Command | Description |
|---------|-------------|
| *(no arguments)* | Start the API server |
| `init` | Write the WireGuard config from `config.yaml`, then exit |
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
| `expiresAt` | no | RFC 3339 time after which the node removes the peer. Omit for a permanent peer; when rotating, omit to keep the current expiry |
| `addressFamilies` | no | `["IPv4"]`, `["IPv6"]` or `["IPv4", "IPv6"]`. Omit to get every family the node has a subnet for. Unknown or repeated values return `400 invalid_address_family`; a family the node has no subnet for returns `400 unsupported_address_family` |

Unknown fields and anything after the JSON object return `400 invalid_json`, so a misspelled field such as `expires_at` can't silently create a permanent peer.

The response has `server` (`publicKey`, `listenPort`) and `peer` (`peerId`, `publicKey`, `privateKey`, `presharedKey`, `allowedIPs`, `addressFamilies`). The node does not store the private key, so this is the only time it is returned.

Returns `409` with `no_available_ip` when the subnet has no free addresses, and `409` with `peer_expired` when rotating a peer whose expiry has passed without a new future `expiresAt`.

### GET /peers/:peerId

The same fields as in the list, plus `receiveBytes` and `transmitBytes` from the kernel. Returns `404` if the peer does not exist.

### DELETE /peers/:peerId

Removes the peer from the interface and from the peer store. Returns `404` if the peer does not exist.

## Peer store persistence

Peers are always stored in a bbolt file, `/var/lib/wgkeeper/peers.db` unless `wireguard.peer_store_file` says otherwise. The node creates the file and its directory on first start. Both compose files mount `./data` there; keep that volume, or every peer is lost when the container is recreated.

The store is the source of truth. On startup the node reconciles the device with it in both directions: peers in the store but missing on the device are added, and peers on the device whose key is not in the store are removed. This also cleans up after a crash in the middle of a write and after manual `wg set` changes: anything not created through the API is gone after a restart.

Every create, rotate, delete and expiry is written to bbolt before the device is changed, under one lock, so concurrent requests for the same peer can't interleave. If the device change fails, the write is rolled back. If the process crashes between the two, the next startup applies the stored state to the device. Clients that already received their keys keep working after a restart.

| Event | What happens |
|-------|-----------|
| Startup, file missing | Creates an empty store and removes all peers from the device |
| Startup, file corrupted or has duplicate `peer_id` / `public_key` | Startup fails with an error |
| Startup, file valid | Adds stored peers to the device and removes device peers that are not in the store |
| Startup, a stored peer is outside the configured subnets, holds the server address, or shares an address with another peer | Startup fails with an error naming the first such peer. Nothing is deleted |
| Peer created, rotated, deleted or expired | Written to the store first, rolled back if the device change fails |
| Host reboot or interface recreated | All stored peers are added back to the device |
| Subnet changed in config | Startup fails while stored peers are outside the new subnets, so a typo can't wipe the store. To change subnets on purpose, delete those peers through the API first |
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

The `path` label is the route template, such as `/peers/:peerId`, so peer IDs don't create new series. Requests to unknown routes are counted as `path="unmatched"`, and methods other than `GET`, `POST`, `DELETE`, `HEAD` and `OPTIONS` as `method="other"`.

Ready-made configs are in [`examples/`](examples): a Prometheus [scrape config](examples/prometheus/prometheus.yml), [alerting rules](examples/prometheus/alerts.yml) for a down node, a failed store rollback, a full subnet and error bursts, and a [Grafana dashboard](examples/grafana/dashboard.json).

Per-peer traffic and handshakes are not exported as metrics: a series per peer grows with every peer and flaps as peers come and go. Use `GET /peers` and `GET /peers/:peerId` for them.

### Keep the metrics port private

The metrics endpoint listens on all interfaces. Peer counts, the version and capacity tell an attacker a lot, so don't expose it to the internet even with the token:

- **Docker:** don't add `9090:9090` to `ports:`. Run Prometheus in the same Compose project and scrape `wireguard:9090` over the Docker network. `docker-compose.local.yml` has a commented-out Prometheus service for this.
- **Docker with Caddy:** same as above. If Prometheus runs elsewhere, add a separate Caddy site (for example `metrics.example.com`) with client certificate (mTLS) auth that proxies to `127.0.0.1:9090`.
- **Bare metal:** allow `9090/tcp` in the firewall only from `127.0.0.1` or your Prometheus host.

## Security

| Mechanism | Details |
|-----------|---------|
| API key | Required on every endpoint except `/healthz` and `/readyz` (`X-API-Key`), compared in constant time, at least 32 characters |
| Error details | Logged with the request ID, never returned to the client |
| HTTPS, IP filtering, rate limiting | In the reverse proxy; see [Using another reverse proxy](#using-another-reverse-proxy). Client addresses, including `X-Forwarded-For`, are only logged, never used for access decisions |
| Peer isolation | Peers reach the internet only; see [Peer isolation](#peer-isolation) |
| Container | `NET_ADMIN` only, `no-new-privileges` |
| Body limit | 256 KB; larger requests get `413` |
| Input validation | Peer IDs must be UUID v4; `offset` and `limit` are range-checked |
| Config validation | `wireguard.routing.wan_interface`, set or detected, is restricted to a safe character set because it is used in iptables rules |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`; HSTS comes from the proxy that terminates TLS |
| Files on disk | WireGuard config and peer store are written with mode `0600`; private keys of peers are never stored |
| Release images | Signed build provenance and an SBOM; see [SECURITY.md](SECURITY.md#verifying-images) |

### Peer isolation

The NAT rules the node writes into `wg0.conf` only let peers out to the internet through the WAN interface. Traffic from peers is dropped when it goes:

- to another peer, or to any interface other than the WAN one;
- to the node itself: the API, metrics and any other service on the host or container. Ping (ICMP) to the server address still works;
- to cloud instance metadata: `169.254.0.0/16`, `100.100.100.200`, `fe80::/10`, `fd00:ec2::254`. Always blocked;
- to private and shared address space: `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`. This covers the host's LAN, the Docker networks and the cloud VPC. Set `wireguard.routing.allow_private_networks: true` if peers need to reach them.

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
