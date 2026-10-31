# Configuration

## Requirements

| | Requirement |
|---|-------------|
| Host | Linux with WireGuard kernel support; root or `CAP_NET_ADMIN` |
| Docker | Capability `NET_ADMIN`. On kernels older than 5.6, load the module on the host (`modprobe wireguard`) instead of granting `SYS_MODULE` |
| Bare metal | `wireguard-tools`, `iproute2`, `iptables` |

## Config file

The node reads `config.yaml` from the working directory. Everything except the API key and a subnet has a default, so the smallest working config is:

```yaml
auth:
  api_key: "<at least 32 characters>"
wireguard:
  subnet: "10.0.0.0/24"
```

[`config.example.yaml`](../config.example.yaml) is a commented example with every key. Unknown keys are errors, so a misspelled key stops the node instead of being ignored.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_CONFIG` | `./config.yaml` | Path of the config file |
| `DEBUG` | off | `true` or `1` turns on debug-level logs. API responses are the same either way: internal error details only go to the log, next to the request's `X-Request-Id` |

## API

| Key | Default | Description |
|-----|---------|-------------|
| `auth.api_key` | required | API key for all protected endpoints, at least 32 characters. Generate one with `openssl rand -hex 32` |
| `server.port` | `51821` | API port. The API is plain HTTP; see [Behind a reverse proxy](deployment.md#behind-a-reverse-proxy) for HTTPS |

The node has no TLS, IP allowlist or rate limit settings; those belong in the reverse proxy in front of it. It refuses to start if the config has `server.tls_cert`, `server.tls_key`, `server.allowed_ips` or `server.trusted_proxies`, which were removed in 2.0.0, so a setup that relied on them is never left unprotected without notice.

## WireGuard

At least one of `wireguard.subnet` and `wireguard.subnet6` is required. Set both for dual-stack.

| Key | Default | Description |
|-----|---------|-------------|
| `wireguard.interface` | `wg0` | Interface name. Up to 15 letters, digits, `-`, `_` and `.` |
| `wireguard.listen_port` | `51820` | WireGuard UDP port |
| `wireguard.subnet` | | IPv4 CIDR for peer addresses, prefix up to `/30` |
| `wireguard.server_ip` | first host of `subnet` | IPv4 address of the server inside `subnet` |
| `wireguard.subnet6` | | IPv6 CIDR for peer addresses, prefix up to `/126` |
| `wireguard.server_ip6` | first host of `subnet6` | IPv6 address of the server inside `subnet6` |
| `wireguard.routing.wan_interface` | interface of the default route | Outbound interface for the NAT rules, for example `eth0`. IPv4 default route first, then IPv6. Set it for policy routing or when the default route is not the way out. Letters, digits, `-`, `_` and `.` only |
| `wireguard.routing.allow_private_networks` | `false` | Let peers reach private and shared address space through the node (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`), for example an office LAN. See [Peer isolation](security.md#peer-isolation) |
| `wireguard.peer_store_file` | `/var/lib/wgkeeper/peers.db` | Path of the [peer store](peer-store.md) |

## Metrics

Metrics are off while `metrics.port` is unset or `0`. See [Metrics](metrics.md).

| Key | Default | Description |
|-----|---------|-------------|
| `metrics.port` | `0` (off) | Port of the `/metrics` endpoint |
| `metrics.token` | required with `metrics.port` | Bearer token for `/metrics`, at least 32 characters and different from `auth.api_key` |
