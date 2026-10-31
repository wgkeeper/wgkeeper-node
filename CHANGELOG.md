# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Each release's notes on GitHub are taken from its section here.

## [Unreleased]

### Changed

- Built with Go 1.27; dependencies updated.
- Runtime image is based on Alpine 3.24 and no longer installs `ca-certificates` (the node makes no outbound TLS connections).

### Security

- Release images ship with a signed build provenance attestation and an SBOM (see [SECURITY.md](SECURITY.md#verifying-images)).

## Earlier releases

Notes for 1.3.1 and earlier are on [GitHub Releases](https://github.com/wgkeeper/wgkeeper-node/releases).

[Unreleased]: https://github.com/wgkeeper/wgkeeper-node/compare/v1.3.1...HEAD
