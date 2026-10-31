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
[![Go](https://img.shields.io/github/go-mod/go-version/wgkeeper/wgkeeper-node)](https://github.com/wgkeeper/wgkeeper-node/blob/main/go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/wgkeeper/wgkeeper-node/badge)](https://scorecard.dev/viewer/?uri=github.com/wgkeeper/wgkeeper-node)

---

WGKeeper Node runs one WireGuard interface on a Linux host and exposes an HTTP API to create, rotate, list and delete its peers. It has no UI and no user accounts: a single orchestrator holds the API key and manages many nodes. That orchestrator can be your own service or [WGKeeper Console](https://github.com/wgkeeper/wgkeeper-console).

- Peers are created with an expiry or as permanent; expired peers are removed by the node itself.
- Keys can be rotated without changing the peer's IP address.
- IPv4, IPv6 or dual-stack, with NAT rules set up for you.
- Peers are stored in a local bbolt file and restored on the interface after every restart.
- Peers get internet access only: they can't reach each other, the node itself, cloud metadata or private networks unless you allow it.
- A small HTTP API with API key auth. HTTPS, IP filtering and rate limits are left to the reverse proxy you already use (Caddy, nginx, anything else); Caddy and nginx examples are included.
- Optional Prometheus metrics on a separate port with its own token.

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

On every start the node writes the WireGuard config from `config.yaml` (addresses, listen port, NAT and isolation rules) and brings the interface up. The server key is generated once and kept, so its public key never changes. From then on, every peer change goes through the API and is stored on disk before it reaches the interface.

## Quick start

Run this on a Linux host with WireGuard support (kernel 5.6+) and Docker.

1. Get the Compose file and the example config:

   ```bash
   git clone https://github.com/wgkeeper/wgkeeper-node.git && cd wgkeeper-node
   cp config.example.yaml config.yaml
   ```

2. Edit `config.yaml`: set `auth.api_key` to a random value (`openssl rand -hex 32`). The outbound interface for NAT is detected from the default route.

3. Start the node:

   ```bash
   docker compose up -d
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

WireGuard listens on `51820/udp`. The API is plain HTTP on `51821`, published on `127.0.0.1` only. To reach it from other machines, put a [reverse proxy](docs/deployment.md#behind-a-reverse-proxy) in front.

## Documentation

- [Configuration](docs/configuration.md): requirements and every `config.yaml` key.
- [Deployment](docs/deployment.md): Docker Compose, reverse proxy (Caddy and nginx examples), building from source.
- [API reference](docs/api.md): endpoints, request fields and errors.
- [Peer store](docs/peer-store.md): how peers are persisted and restored after restarts.
- [Metrics](docs/metrics.md): Prometheus metrics, alerting rules and a Grafana dashboard.
- [Security](docs/security.md): what the node protects and how peers are isolated.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks and the pull request flow, and [CHANGELOG.md](CHANGELOG.md) for changes in each release.

## License

[AGPL-3.0](LICENSE).

WireGuard® is a registered trademark of Jason A. Donenfeld.
