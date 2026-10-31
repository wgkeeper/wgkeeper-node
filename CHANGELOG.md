# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Each release's notes on GitHub are taken from its section here.

## [Unreleased]

Planned as 2.0.0: a major release with breaking changes to the config, the deployment files, the API and the logs. Read the **Breaking** entries before upgrading from 1.x.

The node is now a plain HTTP API with API key auth. HTTPS, client IP filtering and rate limiting move to the reverse proxy in front of it. Peers are always persisted, and the NAT interface is detected automatically.

### Removed

- **Breaking:** `server.tls_cert` and `server.tls_key`. Terminate TLS in a reverse proxy; `examples/caddy` and `examples/nginx` show how.
- **Breaking:** `server.allowed_ips` and `server.trusted_proxies`. Filter clients in the reverse proxy (for example Caddy's `remote_ip` matcher) or in the firewall.
- **Breaking:** the built-in per-IP rate limit for the API. Use the reverse proxy if you need one. The `/metrics` endpoint keeps its own limit.
- **Breaking:** per-peer metrics (`metrics.per_peer`, `metrics.per_peer_max` and the `wgkeeper_peer_rx_bytes_total`, `wgkeeper_peer_tx_bytes_total`, `wgkeeper_peer_last_handshake_seconds`, `wgkeeper_peers_capped` series). A series per peer grows with the peer count and flaps as peers enter and leave the top-N cap. Use `GET /peers` for per-peer traffic and handshakes. The Grafana dashboard drops its per-peer panels.
- **Breaking:** the in-memory peer store. Peers are always written to disk (see Changed).
- **Breaking:** `DEBUG` no longer adds a `detail` field with internal errors to API responses.
- `X-XSS-Protection` and `Strict-Transport-Security` response headers; HSTS belongs to the proxy that terminates TLS.

The node refuses to start if the config still contains a removed key (`server.tls_cert`, `server.tls_key`, `server.allowed_ips`, `server.trusted_proxies`, `metrics.per_peer`, `metrics.per_peer_max`), so an upgraded node never silently runs without something its config asked for. Remove them after moving that protection to the proxy.

### Changed

- **Breaking (logs):** all log keys are snake_case. Audit and error lines use `peer_id`, `public_key`, `allowed_ips`, `address_families` and `expires_at` instead of `peerId`, `publicKey`, `allowedIPs`, `addressFamilies` and `expiresAt`; update log queries and alerts that match on them. The JSON API is unchanged.
- **Breaking:** unknown keys in `config.yaml` stop the node with an error naming the key, instead of being ignored.
- **Breaking:** `POST /peers` rejects unknown JSON fields and trailing data with `400 invalid_json`. A misspelled `expiresAt` used to create a permanent peer.
- `server.port`, `wireguard.interface` and `wireguard.listen_port` default to `51821`, `wg0` and `51820`; the smallest config is `auth.api_key` plus a subnet. `wireguard.interface` must be a valid Linux interface name of up to 15 characters.
- Invalid `addressFamilies` (unknown or repeated values) return `400 invalid_address_family` instead of `500`.
- `401` responses have `"code": "unauthorized"`, like every other error.
- **Breaking:** peers are isolated. The generated `wg0.conf` now drops peer traffic to other peers, to interfaces other than the WAN one, to the node itself (API, metrics, host services; ping still works), to cloud metadata addresses, and to private networks. Before, any peer could reach the node's API and metrics port directly, cloud metadata at `169.254.169.254`, the Docker host and other containers. Set `wireguard.routing.allow_private_networks: true` if peers need private networks such as an office LAN.
- **Breaking:** the compose files no longer grant `SYS_MODULE` and add `no-new-privileges`. On kernels older than 5.6, run `modprobe wireguard` on the host.
- The node logs `X-Forwarded-For` as `forwarded_for` next to the TCP peer address, so the client address is visible behind any proxy without proxy trust settings. `docs/deployment.md` documents what any reverse proxy must do, with nginx and Caddy examples.
- Example configs moved from `docs/` to `examples/`: `nginx/nginx.conf`, `prometheus/prometheus.yml` (now uses `authorization.credentials_file`) and `grafana/dashboard.json`. New `examples/prometheus/alerts.yml` with alerting rules for a down node, a failed peer store rollback, a full subnet and error bursts.
- The README is short; the reference (configuration, deployment, API, peer store, metrics, security) moved to [`docs/`](docs/README.md).
- Compose health checks use `/readyz`, which also checks the WireGuard interface.
- The entrypoint shows `wg-quick` output, so a failed start logs its cause.
- `./data/` (peer store) is ignored by git, and `./wireguard/` and `./data/` are kept out of the Docker build context.
- Peers are always persisted to a bbolt file, `/var/lib/wgkeeper/peers.db` by default; `wireguard.peer_store_file` only changes the path. Both compose files mount `./data` there. If you used `/app/peers/peers.db` with a `./peers` volume, either keep `peer_store_file` and that volume, or move `peers.db` into `./data`.
- `wireguard.routing.wan_interface` is optional: the interface of the default route is used when it is unset.
- `/etc/wireguard/<interface>.conf` is rewritten from `config.yaml` on every start instead of only on the first one, so changed subnets, listen port or WAN interface take effect. The server private key is kept from the existing file; the node refuses to start if that file has no valid `PrivateKey` rather than generating a new one. Manual edits to the file are overwritten.
- `DEBUG` only switches logs to debug level. Errors behind a `4xx`/`5xx` response are always logged with the request ID, method, path and client address.
- **Breaking:** the node no longer ships a proxy. `docker-compose.local.yml` is now `docker-compose.yml` (run `docker compose up -d`); it publishes the API on `127.0.0.1:51821` only, and the health check uses HTTP. `docker-compose.prod-secure.yml` and the `Caddyfile` moved to `examples/caddy/`, next to an nginx example with its own Compose file in `examples/nginx/`. For Caddy, run `docker compose -f docker-compose.yml -f examples/caddy/compose.yml up -d`, and move your edits from the old `Caddyfile` to `examples/caddy/Caddyfile`. Caddy's certificate volumes keep their names.
- `config.example.yaml` no longer contains an `api_key` that the node rejects as too short.
- Built with Go 1.27; dependencies updated.
- Runtime image is based on Alpine 3.24 and no longer installs `ca-certificates` (the node makes no outbound TLS connections).

### Fixed

- A WireGuard device call that times out is no longer treated as failed. The kernel can still apply it later, so rolling back the peer store could lock out a client whose key was rotated, or leave an unmanaged peer whose address was handed out again. The change now stays in the store, the API returns `503 device_timeout`, and a background reconcile brings the device in line with the store once it responds. Retrying the request is safe.
- A hung netlink no longer piles up goroutines or queues every request behind it: while a device call is stuck, new changes fail fast with `503 device_busy` (nothing changed), at most two device reads run at once, and a failed device read is reused for the cache TTL instead of every waiting caller timing out in turn.
- Creating a peer could fail with `409 no_available_ip` on subnets larger than a `/16` (IPv4) or `/112` (IPv6) while free addresses were left: the allocator gave up after 65,536 candidates. Peer addresses now come from a pool that hands out the lowest freed address first, then the next unused one, with no scan limit.
- Expired peers are counted in `wgkeeper_peer_operations_total{op="expire"}`, and failed device changes in `result="error_device"` instead of `error_internal`.
- **Breaking:** the node no longer deletes stored peers that fall outside the configured subnets. A subnet typo used to wipe every peer on the next restart; now startup fails with an error and nothing is deleted. Startup also fails when a stored peer holds the server address or shares an address with another peer.
- Deleting a peer and expiring peers are now write-ahead under the service lock, like create and rotate. Before, the bbolt delete ran after the lock was released: a concurrent create of the same peer could have its new record deleted, and a failed bbolt write could bring a revoked peer back on restart.
- Rotating a peer whose expiry has passed without a new `expiresAt` returns `409 peer_expired` instead of `200` followed by deletion within a minute.
- Shutdown stops the HTTP server before the cleanup loop and the peer store, and a write after the store is closed returns an error instead of silently doing nothing. The compose files set `stop_grace_period: 30s` so Docker doesn't kill the node mid-shutdown.
- A configured `peer_store_file` that did not exist yet was never created, so nothing was persisted until the file was created by hand.

### Performance

Measured with 50,000 peers:

- `GET /peers` builds its device peer index once per device snapshot instead of on every page: 0.03 ms and 47 KB per page instead of 4.4 ms and 14 MB.
- The expiry cleanup removes peers from the sorted index in one pass: 6 ms instead of 110 ms to expire 5,000 peers, and the service lock is held that much shorter.
- Creating a peer after a delete no longer rescans every used address: about 140 ns instead of 2 ms.
- The subnet capacity is computed once at startup instead of on every `/stats`, `/readyz` and metrics scrape (1.5 ms and 1 MB each for an IPv6 `/112`). For subnets larger than 2^53 addresses `/stats` now reports 2^53 instead of 65,536.
- `/readyz` only checks that the WireGuard device can be read, the server key and port are read once, and the device snapshot is reused for 5 s instead of 1 s.

### Security

- Config parse errors no longer print the surrounding YAML lines, which could include `auth.api_key` or `metrics.token`.
- The `method` label of `wgkeeper_http_requests_total` and `wgkeeper_http_request_duration_seconds` is limited to `GET`, `POST`, `DELETE`, `HEAD`, `OPTIONS` and `other`. Requests with arbitrary methods could create unbounded series and exhaust memory.
- `/metrics` checks the bearer token before its rate limit, so unauthenticated requests can't lock out Prometheus; rejected attempts are logged at most once a second.
- The API key and metrics token are compared as SHA-256 digests, so response timing no longer reveals their length.
- The request body of `/peers` is read only after authentication, and both servers accept at most 16 KB of headers.
- A handler panic is logged through slog without request headers; gin's default recovery printed `X-API-Key` in debug mode.
- `metrics.token` is compared to the trimmed `auth.api_key`, so whitespace can't make the two secrets look different.
- Release images ship with a signed build provenance attestation and an SBOM (see [SECURITY.md](SECURITY.md#verifying-images)).

## Earlier releases

Notes for 1.3.1 and earlier are on [GitHub Releases](https://github.com/wgkeeper/wgkeeper-node/releases).

[Unreleased]: https://github.com/wgkeeper/wgkeeper-node/compare/v1.3.1...HEAD
