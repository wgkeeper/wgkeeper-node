# Contributing

Thanks for helping with WGKeeper Node. Bug reports, fixes and docs improvements are welcome. For a new feature or a change in API behavior, please open an issue first so we can agree on the approach before you write code.

Security issues go through [SECURITY.md](SECURITY.md), not public issues.

## Setup

You need:

- Go (the version in `go.mod`);
- Linux with WireGuard to run the node itself (or Docker with `NET_ADMIN`); tests run on any OS;
- [golangci-lint](https://golangci-lint.run/) (the version pinned in `.github/workflows/ci.yml`), [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) and [lefthook](https://github.com/evilmartians/lefthook).

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
lefthook install   # pre-commit: gofmt, go vet; pre-push: lint, tests, govulncheck, go mod tidy
```

## Checks

CI runs the same checks; running them locally saves a round trip.

```bash
go vet ./...
go test -race ./...
golangci-lint run
govulncheck ./...
go mod tidy && git diff --exit-code go.mod go.sum
```

Benchmarks for `internal/wireguard` and `internal/server` run on every pull request and the comparison with `main` is posted as a comment:

```bash
go test -bench=. -benchmem -run='^$' ./internal/wireguard/ ./internal/server/
```

## Pull requests

1. Branch from `main` (`feat/…`, `fix/…`, `docs/…`).
2. Keep a pull request to one change, with tests for new behavior and bug fixes.
3. Title it in [Conventional Commits](https://www.conventionalcommits.org/) style: `feat(metrics): add per-peer metrics`, `fix: IPv4 alloc leak`. The title becomes the squashed commit on `main`.
4. If users will notice the change (API, config, metrics, image, behavior), add a line to `CHANGELOG.md` under `[Unreleased]`.
5. Update `README.md` when you change the API, config keys or deployment.

## Releases (maintainers)

1. Move the `[Unreleased]` entries in `CHANGELOG.md` to a new `## [X.Y.Z] - YYYY-MM-DD` section and update the compare links at the bottom.
2. Merge to `main`, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. CI builds and pushes the multi-arch image (`X.Y.Z`, and `latest` for stable tags), attaches the provenance attestation and SBOM, and creates the GitHub release with that `CHANGELOG.md` section as notes. Tags with a suffix (`v1.4.0-rc.1`) become pre-releases and do not move `latest`.

## License

By contributing you agree that your contributions are licensed under the [AGPL-3.0](LICENSE), the license of this project.
