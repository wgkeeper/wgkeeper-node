# Deployment

On every start the node writes `/etc/wireguard/<interface>.conf` (`./wireguard/<interface>.conf` when not running as root) from `config.yaml`: addresses, listen port and NAT rules. The server private key is generated on the first start and kept in that file afterwards, so the server's public key never changes. Don't edit the file by hand; change `config.yaml` instead. In the Docker image, `entrypoint.sh` then brings the interface up with `wg-quick` and starts the API.

Check the [requirements](configuration.md#requirements) first.

## Docker Compose

[`docker-compose.yml`](../docker-compose.yml) runs `ghcr.io/wgkeeper/node` with `NET_ADMIN` and `no-new-privileges`, mounts `config.yaml`, `./wireguard` and `./data`, publishes `51820/udp` on all interfaces and the API on `127.0.0.1:51821` only, and sets the IPv4/IPv6 forwarding sysctls on an IPv6-capable network. Use the `edge` tag for the latest build from `main`.

```bash
cp config.example.yaml config.yaml
docker compose up -d
```

The API is reachable from this host only. For access from another host, put a reverse proxy in front.

## Behind a reverse proxy

The node only speaks plain HTTP and has no TLS, IP filtering or rate limiting of its own. Use whatever proxy you already run (nginx, Caddy, Traefik, HAProxy, a cloud load balancer), on the host or in Docker. It must:

1. Terminate TLS. Send HSTS from the proxy.
2. Forward to the node over loopback or a private network: `127.0.0.1:51821` from the host, `wireguard:51821` from a container in the same Compose project. Never publish the node's port on a public interface.
3. Filter clients by IP and rate-limit, if you need either. Allowing only your orchestrator is the simplest protection.
4. Set `X-Forwarded-For` to the client address, overwriting any value the client sent. The node logs it as `forwarded_for` next to the TCP peer address; nothing in the node trusts it for access.
5. Allow at least 30s per request and bodies up to 256 KB.
6. Not route `/metrics` or the metrics port through the public site.

If you change `server.port`, change the proxy target and the port in the Compose health check to match.

The repository has two examples. Each has a proxy config and a Compose file that adds the proxy next to the node. Both configs point at `wireguard:51821` and say what to change when the proxy runs on the host instead.

- [`examples/caddy/`](../examples/caddy): Caddy with an automatic Let's Encrypt certificate. Edit the domain in the `Caddyfile`.
- [`examples/nginx/`](../examples/nginx): nginx with an optional IP allowlist and rate limit. nginx doesn't get certificates itself; `compose.yml` shows how to get one with certbot on the host. Edit `server_name` and the certificate paths in `nginx.conf`.

Run from the repository root, with `caddy` or `nginx`:

```bash
docker compose -f docker-compose.yml -f examples/caddy/compose.yml up -d
```

To have plain `docker compose` commands include the proxy, put `COMPOSE_FILE=docker-compose.yml:examples/caddy/compose.yml` in `.env`.

## From source

Requires Go (see `go.mod`) and the bare-metal packages from the [requirements](configuration.md#requirements).

```bash
cp config.example.yaml config.yaml
go run ./cmd/server
```

| Command | Description |
|---------|-------------|
| *(no arguments)* | Start the API server |
| `init` | Write the WireGuard config from `config.yaml`, then exit |
| `init --print-path` | Same as `init`, and print the config path to stdout |
