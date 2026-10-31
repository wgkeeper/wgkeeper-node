# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Each release's notes on GitHub are taken from its section here.

## [Unreleased]

The node is now a plain HTTP API with API key auth. HTTPS, client IP filtering and rate limiting move to the reverse proxy in front of it. Peers are always persisted, and the NAT interface is detected automatically.

### Removed

- **Breaking:** `server.tls_cert` and `server.tls_key`. Terminate TLS in a reverse proxy; `docker-compose.prod-secure.yml` and the `Caddyfile` do this with automatic certificates.
- **Breaking:** `server.allowed_ips` and `server.trusted_proxies`. Filter clients in the reverse proxy (for example Caddy's `remote_ip` matcher) or in the firewall.
- **Breaking:** the built-in per-IP rate limit for the API. Use the reverse proxy if you need one. The `/metrics` endpoint keeps its own limit.
- **Breaking:** per-peer metrics (`metrics.per_peer`, `metrics.per_peer_max` and the `wgkeeper_peer_rx_bytes_total`, `wgkeeper_peer_tx_bytes_total`, `wgkeeper_peer_last_handshake_seconds`, `wgkeeper_peers_capped` series). A series per peer grows with the peer count and flaps as peers enter and leave the top-N cap. Use `GET /peers` for per-peer traffic and handshakes. The Grafana dashboard drops its per-peer panels.
- **Breaking:** the in-memory peer store. Peers are always written to disk (see Changed).
- **Breaking:** `DEBUG` no longer adds a `detail` field with internal errors to API responses.
- `X-XSS-Protection` and `Strict-Transport-Security` response headers; HSTS belongs to the proxy that terminates TLS.

The node refuses to start if the config still contains a removed key (`server.tls_cert`, `server.tls_key`, `server.allowed_ips`, `server.trusted_proxies`, `metrics.per_peer`, `metrics.per_peer_max`), so an upgraded node never silently runs without something its config asked for. Remove them after moving that protection to the proxy.

### Changed

- Peers are always persisted to a bbolt file, `/var/lib/wgkeeper/peers.db` by default; `wireguard.peer_store_file` only changes the path. Both compose files mount `./data` there. If you used `/app/peers/peers.db` with a `./peers` volume, either keep `peer_store_file` and that volume, or move `peers.db` into `./data`.
- `wireguard.routing.wan_interface` is optional: the interface of the default route is used when it is unset.
- `/etc/wireguard/<interface>.conf` is rewritten from `config.yaml` on every start instead of only on the first one, so changed subnets, listen port or WAN interface take effect. The server private key is kept from the existing file; the node refuses to start if that file has no valid `PrivateKey` rather than generating a new one. Manual edits to the file are overwritten.
- `DEBUG` only switches logs to debug level. Errors behind a `4xx`/`5xx` response are always logged with the request ID, method, path and client address.
- `docker-compose.prod-secure.yml`: Caddy now runs in the node container's network namespace and proxies to `127.0.0.1:51821`. Ports `80` and `443` are published on the `wireguard` service. No bridge subnet or proxy trust settings are needed.
- `docker-compose.local.yml`: the API is published on `127.0.0.1:51821` only, and the health check uses HTTP.
- `config.example.yaml` no longer contains an `api_key` that the node rejects as too short.
- Built with Go 1.27; dependencies updated.
- Runtime image is based on Alpine 3.24 and no longer installs `ca-certificates` (the node makes no outbound TLS connections).

### Fixed

- **Breaking:** the node no longer deletes stored peers that fall outside the configured subnets. A subnet typo used to wipe every peer on the next restart; now startup fails with an error and nothing is deleted. Startup also fails when a stored peer holds the server address or shares an address with another peer.
- Deleting a peer and expiring peers are now write-ahead under the service lock, like create and rotate. Before, the bbolt delete ran after the lock was released: a concurrent create of the same peer could have its new record deleted, and a failed bbolt write could bring a revoked peer back on restart.
- Rotating a peer whose expiry has passed without a new `expiresAt` returns `409 peer_expired` instead of `200` followed by deletion within a minute.
- Shutdown stops the HTTP server before the cleanup loop and the peer store, and a write after the store is closed returns an error instead of silently doing nothing. The compose files set `stop_grace_period: 30s` so Docker doesn't kill the node mid-shutdown.
- A configured `peer_store_file` that did not exist yet was never created, so nothing was persisted until the file was created by hand.

### Security

- Release images ship with a signed build provenance attestation and an SBOM (see [SECURITY.md](SECURITY.md#verifying-images)).

## Earlier releases

Notes for 1.3.1 and earlier are on [GitHub Releases](https://github.com/wgkeeper/wgkeeper-node/releases).

[Unreleased]: https://github.com/wgkeeper/wgkeeper-node/compare/v1.3.1...HEAD
