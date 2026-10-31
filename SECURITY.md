# Security policy

WGKeeper Node manages a WireGuard interface and its peers over an HTTP API, so it holds private keys, preshared keys and API credentials, and runs with `NET_ADMIN`. We treat security issues as the highest priority.

Examples of what we consider a vulnerability:

- bypassing API key auth;
- reading or changing peers, keys or node config without a valid API key;
- leaking private keys, preshared keys, the API key or the metrics token (in responses, logs or metrics);
- injecting commands or rules through config values or API input (for example into iptables `PostUp`/`PostDown`);
- crashing or exhausting the node with crafted requests despite the body limit;
- a shipped deployment file (`docker-compose.*.yml`, `Caddyfile`) that exposes the plain HTTP API or the metrics endpoint beyond what it documents;
- a vulnerable dependency or base image that is reachable in the shipped binary or container.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on [wgkeeper/wgkeeper-node](https://github.com/wgkeeper/wgkeeper-node/security/advisories/new). Please do not open a public issue, pull request or discussion.

Include the version or image tag, how the node is deployed (Docker, bare metal, behind a proxy), the steps to reproduce and the impact you see. Remove real keys and tokens first.

What to expect:

- an acknowledgement within 3 working days;
- an assessment and a fix plan within 10 working days;
- a patch release and a published GitHub Security Advisory, crediting you unless you prefer otherwise.

## Supported versions

| Version | Supported |
| --- | --- |
| latest minor release (`1.x`) | yes |
| older releases | no, please upgrade |
| `edge` and `sha-*` images | no, built from `main` for testing |

## Verifying images

Release images on `ghcr.io/wgkeeper/node` are built by GitHub Actions from a tagged commit. Starting with 1.4.0 each image has a signed build provenance attestation and an SBOM. To check that an image was built from this repository:

```bash
gh attestation verify oci://ghcr.io/wgkeeper/node:<version> --owner wgkeeper
```
