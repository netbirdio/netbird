# SyncRequest wire-format fixtures

These files are the frozen byte-for-byte contents of the `SyncRequest` proto a
netbird client of each listed version would put on the wire. `server_sync_legacy_wire_test.go`
decodes each file, wraps it in the current `EncryptedMessage` envelope and
replays it through the in-process gRPC server to prove that the peer-sync fast
path does not break historical clients.

File | Client era | Notes
-----|-----------|------
`v0_20_0.bin` | v0.20.x | `message SyncRequest {}` — no fields on the wire. Main Sync loop in v0.20 gracefully skips nil `NetworkMap`, so the fixture is expected to get a full map (empty Sync payload → cache miss → slow path).
`v0_40_0.bin` | v0.40.x | First release with `Meta` at tag 1. v0.40 calls `GrpcClient.GetNetworkMap` on every OS; fixture must continue to produce a full map.
`v0_60_0.bin` | v0.60.x | Same SyncRequest shape as v0.40 but tagged with a newer `NetbirdVersion`.
`current.bin` | latest | Fully-populated `PeerSystemMeta`.
`android_current.bin` | latest, Android | Same shape as `current.bin` with `GoOS=android`; the server must never take the fast path even after the cache is primed.

## Regenerating

The generator is forward-compatible: it uses the current proto package with only
the fields each era exposes. Re-run after an intentional proto change:

```
go run ./management/server/testdata/sync_request_wire/generate.go
```

and review the byte diff. An unexpected size change or diff indicates the wire
format has drifted — either adjust the generator (if the drift is intentional
and backwards-compatible) or revert the proto change (if it broke old clients).
