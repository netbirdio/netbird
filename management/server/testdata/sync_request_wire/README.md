# SyncRequest wire-format fixtures

These files are the byte-for-byte contents of the `SyncRequest` proto a netbird
client of each listed version would put on the wire. `sync_legacy_wire_test.go`
decodes each file, wraps it in the current `EncryptedMessage` envelope and
replays it through the in-process gRPC server to prove that the peer-sync fast
path does not break historical clients.

File | Client era | Notes
-----|-----------|------
`v0_20_0.bin` | v0.20.x | `message SyncRequest {}` — no fields on the wire. Main Sync loop in v0.20 gracefully skips nil `NetworkMap`, so the fixture is expected to get a full map (empty Sync payload → cache miss → slow path). **Checked in — frozen snapshot.**
`v0_40_0.bin` | v0.40.x | First release with `Meta` at tag 1. v0.40 calls `GrpcClient.GetNetworkMap` on every OS; fixture must continue to produce a full map. **Checked in — frozen snapshot.**
`v0_60_0.bin` | v0.60.x | Same SyncRequest shape as v0.40 but tagged with a newer `NetbirdVersion`. **Checked in — frozen snapshot.**
`current.bin` | latest | Fully-populated `PeerSystemMeta`. **Not checked in — regenerated at CI time by `generate.go`.**
`android_current.bin` | latest, Android | Same shape as `current.bin` with `GoOS=android`; the server must never take the fast path even after the cache is primed. **Not checked in — regenerated at CI time by `generate.go`.**

## Regenerating

`generate.go` writes only `current.bin` and `android_current.bin`. CI invokes it
before running the management test suite:

```sh
go run ./management/server/testdata/sync_request_wire/generate.go
```

Run the same command locally if you are running the wire tests by hand.

The three legacy fixtures are intentionally frozen. Do not regenerate them —
their value is that they survive proto changes unchanged, so a future proto
change that silently breaks the old wire format is caught by CI replaying the
frozen bytes and failing to decode them.
