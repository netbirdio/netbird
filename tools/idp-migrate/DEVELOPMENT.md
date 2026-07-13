# IdP Migration Tool — Developer Guide

## Overview

This tool migrates NetBird deployments from an external IdP (Auth0, Zitadel, Okta, etc.) to the embedded Dex IdP introduced in v0.62.0. It does two things:

1. **DB migration** — Re-encodes every user ID from `{original_id}` to Dex's protobuf-encoded format `base64(proto{original_id, connector_id})`.
2. **Config generation** — Transforms `management.json`: removes `IdpManagerConfig`, `PKCEAuthorizationFlow`, and `DeviceAuthorizationFlow`; strips `HttpConfig` to only `CertFile`/`CertKey`; adds `EmbeddedIdP` with the static connector configuration.

## Code Layout

```
tools/idp-migrate/
├── config.go            # migrationConfig struct, CLI flags, env vars, validation
├── main.go              # CLI entry point, migration phases, config generation
├── main_test.go         # 8 test functions (18 subtests) covering config, connector, URL builder, config generation
└── DEVELOPMENT.md       # this file

management/server/idp/migration/
├── migration.go         # Server interface, MigrateUsersToStaticConnectors(), PopulateUserInfo(), migrateUser(), reconcileActivityStore()
├── migration_test.go    # 6 top-level tests (with subtests) using hand-written mocks
└── store.go             # Store, EventStore interfaces, SchemaCheck, RequiredSchema, SchemaError types

management/server/store/
└── sql_store_idp_migration.go   # CheckSchema(), ListUsers(), UpdateUserInfo(), UpdateUserID(), txDeferFKConstraints() on SqlStore

management/server/activity/store/
├── sql_store_idp_migration.go      # UpdateUserID() on activity Store
└── sql_store_idp_migration_test.go # 5 subtests for activity UpdateUserID

```

## Release / Distribution

The tool is included in `.goreleaser.yaml` as the `netbird-idp-migrate` build target. Each NetBird release produces pre-built archives for Linux (amd64, arm64, arm) that are uploaded to GitHub Releases. The archive naming convention is:

```
netbird-idp-migrate_<version>_linux_<arch>.tar.gz
```

The build requires `CGO_ENABLED=1` because it links the SQLite driver used by `SqlStore`. The cross-compilation setup (CC env for arm64/arm) mirrors the `netbird-mgmt` build.

## CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | *(required)* | Path to management.json |
| `--datadir` | string | *(required)* | Data directory (containing store.db / events.db) |
| `--idp-seed-info` | string | *(required)* | Base64-encoded connector JSON |
| `--domain` | string | `""` | Sets both dashboard and API domain (convenience shorthand) |
| `--dashboard-domain` | string | *(required)* | Dashboard domain (for redirect URIs) |
| `--api-domain` | string | *(required)* | API domain (for Dex issuer and callback URLs) |
| `--dry-run` | bool | `false` | Preview changes without writing |
| `--force` | bool | `false` | Skip interactive confirmation prompt |
| `--skip-config` | bool | `false` | Skip config generation (DB-only migration) |
| `--skip-populate-user-info` | bool | `false` | Skip populating user info (user ID migration only) |
| `--log-level` | string | `"info"` | Log level (debug, info, warn, error) |

## Environment Variables

All flags can be overridden via environment variables. Env vars take precedence over flags.

| Env Var | Overrides |
|---------|-----------|
| `NETBIRD_DOMAIN` | Sets both `--dashboard-domain` and `--api-domain` |
| `NETBIRD_API_URL` | `--api-domain` |
| `NETBIRD_DASHBOARD_URL` | `--dashboard-domain` |
| `NETBIRD_CONFIG_PATH` | `--config` |
| `NETBIRD_DATA_DIR` | `--datadir` |
| `NETBIRD_IDP_SEED_INFO` | `--idp-seed-info` |
| `NETBIRD_DRY_RUN` | `--dry-run` (set to `"true"`) |
| `NETBIRD_FORCE` | `--force` (set to `"true"`) |
| `NETBIRD_SKIP_CONFIG` | `--skip-config` (set to `"true"`) |
| `NETBIRD_SKIP_POPULATE_USER_INFO` | `--skip-populate-user-info` (set to `"true"`) |
| `NETBIRD_LOG_LEVEL` | `--log-level` |

Resolution order: CLI flags are parsed first, then `--domain` sets both URLs, then `NETBIRD_DOMAIN` overrides both, then `NETBIRD_API_URL` / `NETBIRD_DASHBOARD_URL` override individually. After all resolution, `validateConfig()` ensures all required fields are set.

## Migration Flow

### Phase 0: Schema Validation

`validateSchema()` opens the store and calls `CheckSchema(RequiredSchema)` to verify that all tables and columns required by the migration exist in the database. If anything is missing, the tool exits with a descriptive error instructing the operator to start the management server (v0.66.4+) at least once so that automatic GORM migrations create the required schema.

### Phase 1: Populate User Info

Unless `--skip-populate-user-info` is set, `populateUserInfoFromIDP()` runs before connector resolution:

1. Creates an IDP manager from the existing `IdpManagerConfig` in management.json.
2. Calls `idpManager.GetAllAccounts()` to fetch email and name for all users from the external IDP.
3. Calls `migration.PopulateUserInfo()` which iterates over all store users, skipping service users and users that already have both email and name populated. For Dex-encoded user IDs, it decodes back to the original IDP ID for lookup.
4. Updates the store with any missing email/name values.

This ensures user contact info is preserved before the ID migration makes the original IDP IDs inaccessible.

### Phase 2: Connector Decoding

`decodeConnectorConfig()` base64-decodes and JSON-unmarshals the connector JSON provided via `--idp-seed-info` (or `NETBIRD_IDP_SEED_INFO`). It validates that the connector ID is non-empty. There is no auto-detection or fallback — the operator must provide the full connector configuration.

### Phase 3: DB Migration

`migrateDB()` orchestrates the database migration:

1. `openStores()` opens the main store (`SqlStore`) and activity store (non-fatal if missing).
2. Type-asserts both to `migration.Store` / `migration.EventStore`.
3. `previewUsers()` scans all users — counts pending vs already-migrated (using `DecodeDexUserID`).
4. `confirmPrompt()` asks for interactive confirmation (unless `--force` or `--dry-run`).
5. Calls `migration.MigrateUsersToStaticConnectors(srv, conn)`:
   - **Reconciliation pass**: fixes activity store references for users already migrated in the main DB but whose events still reference old IDs (from a previous partial failure).
   - **Main loop**: for each non-migrated user, calls `migrateUser()` which atomically updates the user ID in both the main store and activity store.
   - **Dry-run**: logs what would happen, skips all writes.

`SqlStore.UpdateUserID()` atomically updates the user's primary key and all foreign key references (peers, PATs, groups, policies, jobs, etc.) in a single transaction.

### Phase 4: Config Generation

Unless `--skip-config` is set, `generateConfig()` runs:

1. **Read** — loads existing `management.json` as raw JSON to preserve unknown fields.

2. **Strip** — removes keys that are no longer needed:
   - `IdpManagerConfig`
   - `PKCEAuthorizationFlow`
   - `DeviceAuthorizationFlow`
   - All `HttpConfig` fields except `CertFile` and `CertKey`

3. **Add EmbeddedIdP** — inserts a minimal section with:
   - `Enabled: true`
   - `Issuer` built from `--api-domain` + `/oauth2`
   - `DashboardRedirectURIs` built from `--dashboard-domain` + `/nb-auth` and `/nb-silent-auth`
   - `StaticConnectors` containing the decoded connector, with `redirectURI` overridden to `--api-domain` + `/oauth2/callback`

4. **Write** — backs up original as `management.json.bak`, writes new config. In dry-run mode, prints to stdout instead.

## Interface Decoupling

Migration methods (`ListUsers`, `UpdateUserID`) are **not** on the core `store.Store` or `activity.Store` interfaces. Instead, they're defined in `migration/store.go`:

```go
type Store interface {
    ListUsers(ctx context.Context) ([]*types.User, error)
    UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error
    UpdateUserInfo(ctx context.Context, userID, email, name string) error
    CheckSchema(checks []SchemaCheck) []SchemaError
}

type EventStore interface {
    UpdateUserID(ctx context.Context, oldUserID, newUserID string) error
}
```

A `Server` interface wraps both stores for dependency injection:

```go
type Server interface {
    Store() Store
    EventStore() EventStore // may return nil
}
```

The concrete `SqlStore` types already have these methods (in their respective `sql_store_idp_migration.go` files), so they satisfy the interfaces via Go's structural typing — zero changes needed on the core store interfaces. At runtime, the standalone tool type-asserts:

```go
migStore, ok := mainStore.(migration.Store)
```

This keeps migration concerns completely separate from the core store contract.

## Dex User ID Encoding

`EncodeDexUserID(userID, connectorID)` produces a manually-encoded protobuf with two string fields, then base64-encodes the result (raw, no padding). `DecodeDexUserID` reverses this. The migration loop uses `DecodeDexUserID` to detect already-migrated users (decode succeeds → skip).

See `idp/dex/provider.go` for the implementation.

## Standalone Tool

The standalone tool (`tools/idp-migrate/main.go`) is the primary migration entry point. It opens stores directly, runs schema validation, populates user info from the external IDP, migrates user IDs, and generates the new config — then exits. Configuration is handled entirely through `config.go` which parses CLI flags and environment variables.

## Running Tests

```bash
# Migration library
go test -v ./management/server/idp/migration/...

# Standalone tool
go test -v ./tools/idp-migrate/...

# Activity store migration tests
go test -v -run TestUpdateUserID ./management/server/activity/store/...

# Build locally
go build ./tools/idp-migrate/
```

## Clean Removal

When migration tooling is no longer needed, delete:

1. `tools/idp-migrate/` — entire directory
2. `management/server/idp/migration/` — entire directory
3. `management/server/store/sql_store_idp_migration.go` — migration methods on main SqlStore
4. `management/server/activity/store/sql_store_idp_migration.go` — migration method on activity Store
5. `management/server/activity/store/sql_store_idp_migration_test.go` — tests for the above
6. In `.goreleaser.yaml`:
   - Remove the `netbird-idp-migrate` build entry
   - Remove the `netbird-idp-migrate` archive entry
7. Run `go mod tidy`

No core interfaces or mocks need editing — that's the point of the decoupling.
