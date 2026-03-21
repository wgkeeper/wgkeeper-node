# Benchmark Snapshot

Date: 2026-03-21
Host: darwin arm64  
Go packages: `./internal/wireguard ./internal/server`  
Command:

```bash
go test -bench=. -benchmem -benchtime=1s -count=3 -run='^$' ./internal/wireguard ./internal/server
```

Values below use the median of 3 runs for readability.

## What Is Measured

- `internal/wireguard`: IP allocation, peer lifecycle operations, in-memory `PeerStore` throughput, and bbolt persistence I/O.
- `internal/server`: REST handler and middleware overhead in test mode.
- Parallel benchmarks (`*Parallel`) show behavior under concurrent access.

## How To Read The Metrics

- `ns/op`: lower is faster.
- `B/op`: memory allocated per operation, lower usually means less GC pressure.
- `allocs/op`: number of allocations per operation; zero-allocation hot paths are preferred.

## What Is One Operation

- In Go benchmarks, `op` means one full iteration of the benchmark body.
- Example: in `BenchmarkGetPeerHandler`, one operation is one call to `router.ServeHTTP(...)`, which is one synthetic HTTP request through the handler stack.
- Example: in `BenchmarkCreatePeerHandler`, one operation is one synthetic `POST /peers` request.
- For `PeerStore` benchmarks, one operation is one store call (`Get`, `Set`, `ListPaginated`, or `ForEach`).

## Single-Thread vs Parallel Benchmarks

- Regular benchmarks (`BenchmarkXxx`) run in a tight loop and represent a single-worker baseline.
- Parallel benchmarks (`BenchmarkXxxParallel`) use `b.RunParallel`, so multiple goroutines execute concurrently.
- Metrics in parallel mode are still reported per operation, but measured under contention and scheduler effects.

## How To Relate This To Real Load

- These are in-process `httptest` benchmarks: no real network latency, no TLS handshake, no reverse proxy, and no kernel/socket overhead.
- Treat numbers as a stable code-level baseline and for before/after comparisons, not as direct production RPS.
- For production-facing validation, combine these results with load tests against a deployed binary and compare percentile latency (`p50`, `p95`, `p99`).

## Scope Limitation

- These benchmarks cover control-plane paths only (API handlers, middleware, peer lifecycle logic, and in-memory store behavior).
- Real WireGuard kernel data-plane performance is out of scope here: packet encryption/decryption throughput, forwarding rate, and kernel network stack behavior are not measured.
- Use separate tunnel-level tests (for example, `iperf3` through an active WireGuard tunnel) to evaluate kernel path performance.

## Quick Interpretation

- `PeerStore` is very fast and allocation-free on core `Get` and `Set` paths.
- `PersistPut` (~5.9 ms) is dominated by bbolt's fsync-per-commit guarantee — this is the cost of durability, not code overhead. In-memory operations are unaffected.
- `OpenFile` (~472 µs for 200 peers) is a one-time startup cost; irrelevant to steady-state throughput.
- API handlers are fast in absolute terms (sub-microsecond to low-microsecond range), with moderate allocation cost.
- `BenchmarkAllocateOneIPv4NearlyFull` is intentionally a worst-case scenario and expected to be slower.
- Current performance baseline is strong; the largest optimization headroom is reducing API handler allocations.

## Benchmark Legend

- `BenchmarkAllocateOneIPv4`: allocate one IPv4 address in a typical free-space case.
- `BenchmarkAllocateOneIPv4NearlyFull`: allocate one IPv4 address when the subnet is almost exhausted (worst case).
- `BenchmarkAllocateOneIPv6`: allocate one IPv6 address in a typical free-space case.
- `BenchmarkEnsurePeerRotate`: rotate an existing peer (refresh keys/expiry).
- `BenchmarkEnsurePeerNew`: create a new peer with address assignment and key generation.
- `BenchmarkDeletePeer`: delete an existing peer and cleanup related state.
- `BenchmarkPeerStoreSet`: write/update one peer record in the in-memory store.
- `BenchmarkPeerStoreGet`: read one peer record by ID from the in-memory store.
- `BenchmarkPeerStoreGetParallel`: concurrent read pressure on `PeerStore.Get`.
- `BenchmarkPeerStoreSetParallel`: concurrent write pressure on `PeerStore.Set`.
- `BenchmarkPeerStoreListPaginated1000`: fetch one paginated page from a 1000-record store.
- `BenchmarkPeerStoreForEach1000`: iterate all records in a 1000-record store.
- `BenchmarkPeerStorePersistPut`: write one peer record to the open bbolt DB (one fsync per call).
- `BenchmarkPeerStoreOpenFile`: open an existing bbolt DB and load 200 peer records into memory (startup cost).
- `BenchmarkListPeersHandler`: process one `GET /peers` request in test mode.
- `BenchmarkCreatePeerHandler`: process one `POST /peers` request in test mode.
- `BenchmarkGetPeerHandler`: process one `GET /peers/:peerId` request in test mode.
- `BenchmarkListPeersHandlerParallel`: concurrent `GET /peers` handler pressure.
- `BenchmarkGetPeerHandlerParallel`: concurrent `GET /peers/:peerId` handler pressure.
- `BenchmarkAPIKeyMiddleware`: one request through API key auth middleware.

## internal/wireguard

| Benchmark | ns/op (median) | B/op | allocs/op |
|---|---:|---:|---:|
| BenchmarkAllocateOneIPv4 | 180.7 | 325 | 8 |
| BenchmarkAllocateOneIPv4NearlyFull | 13814 | 8064 | 510 |
| BenchmarkAllocateOneIPv6 | 281.9 | 360 | 9 |
| BenchmarkEnsurePeerRotate | 44123 | 1376 | 25 |
| BenchmarkEnsurePeerNew | 45760 | 1904 | 36 |
| BenchmarkDeletePeer | 2571 | 704 | 10 |
| BenchmarkPeerStoreSet | 33.80 | 0 | 0 |
| BenchmarkPeerStoreGet | 23.43 | 0 | 0 |
| BenchmarkPeerStoreGetParallel | 159.5 | 0 | 0 |
| BenchmarkPeerStoreSetParallel | 140.2 | 0 | 0 |
| BenchmarkPeerStoreListPaginated1000 | 1377 | 6912 | 1 |
| BenchmarkPeerStoreForEach1000 | 13620 | 0 | 0 |
| BenchmarkPeerStorePersistPut | 5894497 | 19988 | 55 |
| BenchmarkPeerStoreOpenFile | 472171 | 284596 | 3860 |

## internal/server

| Benchmark | ns/op (median) | B/op | allocs/op |
|---|---:|---:|---:|
| BenchmarkListPeersHandler | 5583 | 8444 | 17 |
| BenchmarkCreatePeerHandler | 3732 | 8305 | 40 |
| BenchmarkGetPeerHandler | 959.0 | 1441 | 11 |
| BenchmarkListPeersHandlerParallel | 2884 | 8509 | 17 |
| BenchmarkGetPeerHandlerParallel | 571.3 | 1442 | 11 |
| BenchmarkAPIKeyMiddleware | 191.0 | 224 | 5 |

## Notes

- Benchmarks are environment-sensitive; compare primarily within the same host, CPU, and Go version.
- For regression decisions, rely on base-vs-PR CI comparison (`benchstat`) rather than absolute local numbers.
