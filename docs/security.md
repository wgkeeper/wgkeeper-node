# Security

To report a vulnerability, see [SECURITY.md](../SECURITY.md). Please don't open a public issue.

| Mechanism | Details |
|-----------|---------|
| API key | Required on every endpoint except `/healthz` and `/readyz` (`X-API-Key`), compared in constant time, at least 32 characters |
| Error details | Logged with the request ID, never returned to the client |
| HTTPS, IP filtering, rate limiting | In the reverse proxy; see [Behind a reverse proxy](deployment.md#behind-a-reverse-proxy). Client addresses, including `X-Forwarded-For`, are only logged, never used for access decisions |
| Peer isolation | Peers reach the internet only; see [below](#peer-isolation) |
| Container | `NET_ADMIN` only, `no-new-privileges` |
| Body limit | 256 KB; larger requests get `413` |
| Input validation | Peer IDs must be UUID v4; `offset` and `limit` are range-checked |
| Config validation | `wireguard.routing.wan_interface`, set or detected, is restricted to a safe character set because it is used in iptables rules |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`; HSTS comes from the proxy that terminates TLS |
| Files on disk | WireGuard config and [peer store](peer-store.md) are written with mode `0600`; private keys of peers are never stored |
| Release images | Signed build provenance and an SBOM; see [SECURITY.md](../SECURITY.md#verifying-images) |

## Peer isolation

The NAT rules the node writes into `wg0.conf` only let peers out to the internet through the WAN interface. Traffic from peers is dropped when it goes:

- to another peer, or to any interface other than the WAN one;
- to the node itself: the API, metrics and any other service on the host or container. Ping (ICMP) to the server address still works;
- to cloud instance metadata: `169.254.0.0/16`, `100.100.100.200`, `fe80::/10`, `fd00:ec2::254`. Always blocked;
- to private and shared address space: `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`. This covers the host's LAN, the Docker networks and the cloud VPC. Set `wireguard.routing.allow_private_networks: true` if peers need to reach them.
