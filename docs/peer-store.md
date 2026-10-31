# Peer store

Peers are always stored in a bbolt file, `/var/lib/wgkeeper/peers.db` unless `wireguard.peer_store_file` says otherwise. The node creates the file and its directory on first start. The Compose file mounts `./data` there; keep that volume, or every peer is lost when the container is recreated.

The store is the source of truth. On startup the node reconciles the device with it in both directions: peers in the store but missing on the device are added, and peers on the device whose key is not in the store are removed. This also cleans up after a crash in the middle of a write and after manual `wg set` changes: anything not created through the API is gone after a restart.

Every create, rotate, delete and expiry is written to bbolt before the device is changed, under one lock, so concurrent requests for the same peer can't interleave. If the device change fails, the write is rolled back. If the process crashes between the two, the next startup applies the stored state to the device. Clients that already received their keys keep working after a restart.

| Event | What happens |
|-------|-----------|
| Startup, file missing | Creates an empty store and removes all peers from the device |
| Startup, file corrupted or has duplicate `peer_id` / `public_key` | Startup fails with an error |
| Startup, file valid | Adds stored peers to the device and removes device peers that are not in the store |
| Startup, a stored peer is outside the configured subnets, holds the server address, or shares an address with another peer | Startup fails with an error naming the first such peer. Nothing is deleted |
| Peer created, rotated, deleted or expired | Written to the store first, rolled back if the device change fails |
| Host reboot or interface recreated | All stored peers are added back to the device |
| Subnet changed in config | Startup fails while stored peers are outside the new subnets, so a typo can't wipe the store. To change subnets on purpose, delete those peers through the API first |
| `expiresAt` reached | A background task removes the peer |

The file stores `peer_id`, `public_key`, `preshared_key`, `allowed_ips`, `created_at` and `expires_at` per peer, never private keys. It is created with mode `0600`; keep its directory closed to other users as well.
