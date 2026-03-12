# IdP Migration Tool — Developer Guide

## Overview

This tool migrates NetBird deployments from an external IdP (Auth0, Zitadel, Okta, etc.) to the embedded Dex IdP introduced in v0.60.0. It does two things:

1. **DB migration** — Re-encodes every user ID from `{original_id}` to Dex's protobuf-encoded format `base64(proto{original_id, connector_id})`.
2. **Config generation** — Transforms `management.json` by replacing `IdpManagerConfig` with `EmbeddedIdP` and updating `HttpConfig` fields.

## Code Layout

```
tools/idp-migrate/
├── main.go          # CLI entry point, connector resolution, config generation
├── main_test.go     # 27 tests covering all exported/internal functions
└── DEVELOPMENT.md   # this file

management/server/idp/migration/
├── migration.go     # MigrateUsersToStaticConnectors(), migrateUser(), reconcileActivityStore()
├── migration_test.go # 14 tests with hand-written mocks
└── store.go         # MigrationStore, MigrationEventStore interfaces

management/internals/server/modules.go
  └── seedIDPConnectors()   # combined server path (uses same migration code)
      migrationServer       # adapter struct for type assertions
```

## CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | *(required)* | Path to management.json |
| `--datadir` | string | `""` | Override data directory from config |
| `--idp-seed-info` | string | `""` | Base64-encoded connector JSON (overrides auto-detection) |
| `--dry-run` | bool | `false` | Preview changes without writing |
| `--force` | bool | `false` | Skip interactive confirmation prompt |
| `--skip-config` | bool | `false` | Skip config generation (DB-only migration) |
| `--log-level` | string | `"info"` | Log level (debug, info, warn, error) |

## Migration Flow

### Phase 1: Connector Resolution

`resolveConnector()` uses a 3-tier priority:

1. `--idp-seed-info` flag — explicit base64-encoded connector JSON
2. `IDP_SEED_INFO` env var — same format, read via `migration.SeedConnectorFromEnv()`
3. Auto-detect from `management.json` — reads `IdpManagerConfig.ClientConfig` fields and maps `ManagerType` to a Dex connector type:

| ManagerType | Dex Connector Type |
|-------------|--------------------|
| `zitadel` | `zitadel` |
| `keycloak` | `keycloak` |
| `okta` | `okta` |
| `authentik` | `authentik` |
| `pocketid` | `pocketid` |
| `auth0` | `oidc` (generic) |
| `azure` | `entra` |
| `google` | `google` |
| `jumpcloud` | **error** (unsupported) |
| *(unknown)* | `oidc` (fallback) |

### Phase 2: DB Migration

1. Opens the main store (`SqlStore`) and activity store (non-fatal if missing).
2. Type-asserts both to `migration.MigrationStore` / `migration.MigrationEventStore`.
3. Scans all users — counts pending vs already-migrated (using `DecodeDexUserID`).
4. Calls `migration.MigrateUsersToStaticConnectors(srv, conn)`:
   - **Reconciliation pass**: fixes activity store references for users already migrated in the main DB but whose events still reference old IDs (from a previous partial failure).
   - **Main loop**: for each non-migrated user, calls `migrateUser()` which atomically updates the user ID in both the main store and activity store.
   - **Dry-run**: logs what would happen, skips all writes.

`SqlStore.UpdateUserID()` atomically updates the user's primary key and all foreign key references (peers, PATs, groups, policies, jobs, etc.) in a single transaction.

### Phase 3: Config Generation

Unless `--skip-config` is set:

1. **Derive domain** — `deriveDomain()` priority:
   1. `HttpConfig.LetsEncryptDomain` (most explicit)
   2. Parse host from `HttpConfig.OIDCConfigEndpoint`
   3. Parse host from `HttpConfig.AuthIssuer`
   4. Parse host from `IdpManagerConfig.ClientConfig.Issuer` (last resort)

2. **Transform JSON** — reads existing config as raw JSON to preserve all fields, then:
   - Removes `IdpManagerConfig`
   - Adds `EmbeddedIdP` with the static connector, redirect URIs, etc.
   - Updates `HttpConfig.AuthIssuer`, `AuthKeysLocation`, `OIDCConfigEndpoint`, `AuthClientID`
   - Sets `AuthUserIDClaim` to `"sub"` only if not already set

3. **Write** — backs up original as `management.json.bak`, writes new config. In dry-run mode, prints to stdout instead.

## Interface Decoupling

Migration methods (`ListUsers`, `UpdateUserID`) are **not** on the core `store.Store` or `activity.Store` interfaces. Instead, they're defined in `migration/store.go`:

```go
type MigrationStore interface {
    ListUsers(ctx context.Context) ([]*types.User, error)
    UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error
}

type MigrationEventStore interface {
    UpdateUserID(ctx context.Context, oldUserID, newUserID string) error
}
```

The concrete `SqlStore` types already have these methods, so they satisfy the interfaces via Go's structural typing — zero changes needed on the store implementations. At runtime, both the standalone tool and the combined server type-assert:

```go
migStore, ok := mainStore.(migration.MigrationStore)
```

This keeps migration concerns completely separate from the core store contract.

## Dex User ID Encoding

`EncodeDexUserID(userID, connectorID)` produces a manually-encoded protobuf with two string fields, then base64-encodes the result (raw, no padding). `DecodeDexUserID` reverses this. The migration loop uses `DecodeDexUserID` to detect already-migrated users (decode succeeds → skip).

See `idp/dex/provider.go` for the implementation.

## Combined Server vs Standalone Tool

| Aspect | Standalone Tool | Combined Server |
|--------|----------------|-----------------|
| Trigger | `netbird-idp-migrate --config ...` | `IDP_SEED_INFO` env var at startup |
| Connector source | 3-tier priority | Env var only |
| Config generation | Yes (transforms management.json) | No (config managed by getting-started.sh) |
| Store access | Opens stores directly | Uses `AfterInit` hook after stores are initialized |
| Lifecycle | Exits after migration | Server continues running |
| Entry point | `tools/idp-migrate/main.go` | `modules.go:seedIDPConnectors()` |

Both paths call the same `migration.MigrateUsersToStaticConnectors()` function.

## Running Tests

```bash
# Migration library
go test -v ./management/server/idp/migration/...

# Standalone tool
go test -v ./tools/idp-migrate/...

# Build
go build ./tools/idp-migrate/
```

## Clean Removal

When migration tooling is no longer needed, delete:

1. `tools/idp-migrate/` — entire directory
2. `management/server/idp/migration/` — entire directory
3. In `management/internals/server/modules.go`:
   - Remove the `migration` import
   - Remove `migrationServer` struct and methods
   - Remove `seedIDPConnectors()` method
   - Remove the `s.seedIDPConnectors()` call in `IdpManager()`
4. Optionally remove the now-dead methods from concrete store types:
   - `SqlStore.ListUsers()` and `SqlStore.UpdateUserID()` in `management/server/store/sql_store.go`
   - `Store.UpdateUserID()` in `management/server/activity/store/sql_store.go`
5. Run `go mod tidy`

No core interfaces or mocks need editing — that's the point of the decoupling.
