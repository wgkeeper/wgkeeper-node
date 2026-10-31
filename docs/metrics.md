# Metrics

The node can serve Prometheus metrics at `/metrics` on a separate port. It is off until `metrics.port` is set. The endpoint requires a bearer token that is separate from the API key and is rate limited to 5 requests per second.

```yaml
metrics:
  port: 9090
  token: "<at least 32 characters, e.g. openssl rand -hex 32>"
```

With `metrics.port` set, the token is required: at least 32 characters and different from `auth.api_key`, or the node refuses to start.

## Exported metrics

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

Ready-made configs are in [`examples/`](../examples): a Prometheus [scrape config](../examples/prometheus/prometheus.yml), [alerting rules](../examples/prometheus/alerts.yml) for a down node, a failed store rollback, a full subnet and error bursts, and a [Grafana dashboard](../examples/grafana/dashboard.json).

Per-peer traffic and handshakes are not exported as metrics: a series per peer grows with every peer and flaps as peers come and go. Use `GET /peers` and `GET /peers/:peerId` for them.

## Keep the metrics port private

The metrics endpoint listens on all interfaces. Peer counts, the version and capacity tell an attacker a lot, so don't expose it to the internet even with the token:

- **Docker:** don't add `9090:9090` to `ports:`. Run Prometheus in the same Compose project and scrape `wireguard:9090` over the Docker network. [`docker-compose.yml`](../docker-compose.yml) has a commented-out Prometheus service for this. If Prometheus runs elsewhere, add a separate site in your reverse proxy (for example `metrics.example.com`) with client certificate (mTLS) auth that proxies to the metrics port.
- **Bare metal:** allow `9090/tcp` in the firewall only from `127.0.0.1` or your Prometheus host.
