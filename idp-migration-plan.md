# Plan: Standalone IdP Migration Tool (External IdP → Embedded DEX)

## Context

**Target repo:** `/Users/ashleymensah/Documents/netbird-repos/netbird` (main repo, not the fork)

Self-hosted NetBird users migrating from an external IdP (Zitadel, Keycloak, Okta, etc.) to NetBird's embedded DEX-based IdP need a way to re-key all user IDs in the database. A colleague's fork at `/Users/ashleymensah/Documents/netbird-repos/nico-netbird/netbird` has a prototype that runs inside management as an AfterInit hook, but this has a chicken-and-egg problem (enabling EmbeddedIdP causes management to initialize DEX before migration runs → startup failure).

This plan creates a **standalone CLI tool** that runs with management stopped, re-keys all user IDs, then the user manually updates their management config and restarts. The main repo already has DEX/EmbeddedIdP infrastructure but is missing the store methods and migration logic — these need to be created (porting patterns from the fork).

**Note:** Does not need to work with the combined management container setup (that only supports embeddedIdP-enabled setups anyway).

---

## What the migration does

For each user, transforms the old ID (e.g., a Zitadel UUID) into DEX's encoded format:
```
newID = EncodeDexUserID(oldUserID, connectorID)
       → base64(protobuf{field1: userID, field2: connectorID})
```
This encoded ID is what DEX puts in JWT `sub` claims, ensuring continuity after switching IdPs.

---

## Tables requiring user ID updates

### Main store (store.db / PostgreSQL) — 10 columns

| # | Table | Column | Notes |
|---|-------|--------|-------|
| 1 | `users` | `id` (PK) | Primary key update, done last in transaction |
| 2 | `personal_access_tokens` | `user_id` (FK) | |
| 3 | `personal_access_tokens` | `created_by` | |
| 4 | `peers` | `user_id` | |
| 5 | `user_invites` | `created_by` | GORM `TableName()` returns `user_invites` (not `user_invite_records`) |
| 6 | `accounts` | `created_by` | |
| 7 | `proxy_access_tokens` | `created_by` | |
| 8 | `jobs` | `triggered_by` | |
| 9 | `policy_rules` | `authorized_user` | SSH policy user refs — missed by fork's implementation |
| 10 | `access_log_entries` | `user_id` | Reverse proxy access logs — missed by both fork and original plan |

### Activity store (events.db / PostgreSQL) — 3 columns

| # | Table | Column | Notes |
|---|-------|--------|-------|
| 10 | `events` | `initiator_id` | |
| 11 | `events` | `target_id` | |
| 12 | `deleted_users` | `id` (PK) | Raw SQL needed (GORM can't update PK via Model) |

**Total: 13 columns (10 main store + 3 activity store)**

### Verified NOT needing migration
- `policy_rules.authorized_groups` — maps group IDs → local Unix usernames (e.g., "root", "admin"), NOT NetBird user IDs
- `groups` / `group_peers` — store peer IDs, not user IDs
- `routes`, `nameserver_groups`, `setup_keys`, `posture_checks`, `networks`, `dns_settings` — no user ID fields

---

## What exists in main repo vs what needs to be created

| Component | Main repo status | Action |
|-----------|-----------------|--------|
| `EncodeDexUserID` / `DecodeDexUserID` | EXISTS at `idp/dex/provider.go` | No changes |
| EmbeddedIdP config + manager | EXISTS at `management/server/idp/embedded.go` | No changes |
| DEX provider | EXISTS at `idp/dex/provider.go` | No changes |
| Server bootstrapping (modules.go) | EXISTS at `management/internals/server/modules.go` | No changes |
| `Store.ListUsers()` interface method | **MISSING** | Add to `management/server/store/store.go` |
| `SqlStore.ListUsers()` implementation | **MISSING** | Add to `management/server/store/sql_store.go` |
| `Store.UpdateUserID()` interface method | **MISSING** | Add to `management/server/store/store.go` |
| `SqlStore.UpdateUserID()` implementation | **MISSING** | Add to `management/server/store/sql_store.go` |
| `activity.Store.UpdateUserID()` interface | **MISSING** | Add to `management/server/activity/store.go` |
| Activity `Store.UpdateUserID()` implementation | **MISSING** | Add to `management/server/activity/store/sql_store.go` |
| `InMemoryEventStore.UpdateUserID()` no-op | **MISSING** | Add to `management/server/activity/store.go` (compile-blocking) |
| `txDeferFKConstraints` helper | **MISSING** | Port from fork to `management/server/store/sql_store.go` |
| Store mock regeneration | **NEEDED** | Run `go generate ./management/server/store/...` after interface changes |
| Migration package | **MISSING** | Create at `management/server/idp/migration/` |
| Standalone CLI tool | **MISSING** | Create at `management/cmd/migrate-idp/` |

**Source of patterns:** Fork at `/Users/ashleymensah/Documents/netbird-repos/nico-netbird/netbird`

---

## Implementation plan

### Step 1: Add `ListUsers()` to store interface and implementation

**File:** `management/server/store/store.go` — add to Store interface:
```go
ListUsers(ctx context.Context) ([]*types.User, error)
```

**File:** `management/server/store/sql_store.go` — add implementation:
```go
func (s *SqlStore) ListUsers(ctx context.Context) ([]*types.User, error) {
    var users []*types.User
    if err := s.db.Find(&users).Error; err != nil {
        return nil, status.Errorf(status.Internal, "failed to list users")
    }
    // Decrypt sensitive fields (Email, Name) so logging shows readable values.
    // No-op when fieldEncrypt is nil (no encryption key configured).
    for _, user := range users {
        if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
            return nil, status.Errorf(status.Internal, "failed to decrypt user data")
        }
    }
    return users, nil
}
```

### Step 2: Add `UpdateUserID()` to store interface and implementation

**File:** `management/server/store/store.go` — add to Store interface:
```go
UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error
```

**File:** `management/server/store/sql_store.go` — add implementation (ported from fork, with `policy_rules` fix):
```go
func (s *SqlStore) UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error {
    updates := []fkUpdate{
        {&types.PersonalAccessToken{}, "user_id", "user_id = ?"},
        {&types.PersonalAccessToken{}, "created_by", "created_by = ?"},
        {&nbpeer.Peer{}, "user_id", "user_id = ?"},
        {&types.UserInviteRecord{}, "created_by", "created_by = ?"},
        {&types.Account{}, "created_by", "created_by = ?"},
        {&types.ProxyAccessToken{}, "created_by", "created_by = ?"},
        {&types.Job{}, "triggered_by", "triggered_by = ?"},
        {&types.PolicyRule{}, "authorized_user", "authorized_user = ?"},  // missed by fork
        {&accesslogs.AccessLogEntry{}, "user_id", "user_id = ?"},       // missed by both fork and original plan
    }
    // Transaction with deferred FK constraints, update FKs first, then users.id PK
    // Note: txDeferFKConstraints helper must be ported from fork (does not exist in main repo)
    // - SQLite: PRAGMA defer_foreign_keys = ON
    // - PostgreSQL: SET CONSTRAINTS ALL DEFERRED (belt-and-suspenders; FK-first update order
    //   already handles non-deferrable constraints)
    // - MySQL: handled by existing transaction() helper (SET FOREIGN_KEY_CHECKS = 0)
}
```

### Step 2b: Port `txDeferFKConstraints` helper

**File:** `management/server/store/sql_store.go` — add helper (ported from fork lines 842-853):
```go
func (s *SqlStore) txDeferFKConstraints(tx *gorm.DB) error {
    // SQLite: defer FK checks until transaction commit
    // PostgreSQL: defer constraints (belt-and-suspenders; update order handles non-deferrable)
    // MySQL: already handled by transaction() wrapper
}
```

### Step 3: Add `UpdateUserID()` to activity store interface and implementation

**File:** `management/server/activity/store.go` — add to Store interface:
```go
UpdateUserID(ctx context.Context, oldUserID, newUserID string) error
```

**File:** `management/server/activity/store.go` — add no-op to `InMemoryEventStore` (compile-blocking):
```go
func (store *InMemoryEventStore) UpdateUserID(_ context.Context, _, _ string) error {
    return nil
}
```

**File:** `management/server/activity/store/sql_store.go` — add implementation (ported from fork):
- Update `events.initiator_id` and `events.target_id` via GORM
- Update `deleted_users.id` via raw SQL (GORM can't update PK via Model)
- All in one transaction

### Step 3b: Regenerate store mocks

Run `go generate ./management/server/store/...` to regenerate `store_mock.go` with the new `ListUsers` and `UpdateUserID` methods. Without this, tests using the mock won't compile.

### Step 4: Create migration package

**New file:** `management/server/idp/migration/migration.go`

- Define narrow interfaces:
  ```go
  type MainStoreUpdater interface {
      ListUsers(ctx context.Context) ([]*types.User, error)
      UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error
  }
  type ActivityStoreUpdater interface {
      UpdateUserID(ctx context.Context, oldUserID, newUserID string) error
  }
  ```
- `MigrationConfig` struct: `ConnectorID`, `DryRun`, `MainStore`, `ActivityStore`
- `MigrationResult` struct: `Migrated`, `Skipped` counts
- `Migrate(ctx, *MigrationConfig) (*MigrationResult, error)`:
  1. List all users from main store
  2. Reconciliation pass: for already-migrated users, ensure activity store is also updated
  3. For each non-migrated user: encode new ID, update both stores
  4. Return counts
- Idempotency: `DecodeDexUserID(user.Id)` succeeds → user already migrated, skip
- Empty-ID guard: skip users with `Id == ""` before the decode check (`DecodeDexUserID("")` succeeds with empty strings — edge case)
- Service users: `IsServiceUser=true` users get re-keyed like all others (they'll be looked up by the new DEX-encoded ID after migration). This is intentional — document in CLI help text.
- Uses `EncodeDexUserID` / `DecodeDexUserID` from `idp/dex/provider.go`

**New file:** `management/server/idp/migration/migration_test.go`

- Mock-based tests for `Migrate()` covering: normal migration, skip already-migrated, dry-run, reconciliation, empty user list, error handling

### Step 5: Build the standalone CLI tool

**New file:** `management/cmd/migrate-idp/main.go` (~200 lines)

CLI flags:
| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--config` | Yes | `/etc/netbird/management.json` | Path to management config |
| `--connector-id` | Yes | — | DEX connector ID to encode into user IDs |
| `--dry-run` | No | `false` | Preview changes without writing |
| `--no-backup` | No | `false` | Skip automatic database backup |
| `--log-level` | No | `info` | Verbosity |

Flow:
1. Load management config JSON (reuse `util.ReadJsonWithEnvSub`)
2. Validate: connector-id is non-empty, DB is accessible
3. Open main store via `store.NewStore(ctx, engine, datadir, nil, false)` — nil metrics, run AutoMigrate
   - `skipMigration=false` ensures schema is up-to-date (AutoMigrate is idempotent/non-destructive)
   - Using `true` risks stale schema if user upgrades management + tool simultaneously
4. Call `store.SetFieldEncrypt(enc)` to enable field decryption (needed for `ListUsers` to return readable Email/Name for logging)
5. Open activity store via `activity_store.NewSqlStore(ctx, datadir, encryptionKey)`
   - Gracefully handle missing activity store (e.g., `events.db` doesn't exist) — warn and skip activity migration
6. Backup databases (SQLite: file copy; PostgreSQL: print `pg_dump` instructions)
7. Call `migration.Migrate(ctx, cfg)`
8. Print summary and exit

**New file:** `management/cmd/migrate-idp/backup.go` (~60 lines)
- `backupSQLiteFile(srcPath)` — copies to `{src}.backup-{timestamp}`

### Step 6: Tests

- Unit tests in `migration_test.go` with mock interfaces
- Integration test in `management/cmd/migrate-idp/main_test.go` with real SQLite:
  - Seed users, events, policy rules with `authorized_user`, access log entries with `user_id`
  - Run migration, verify all 13 columns updated
  - Run again, verify idempotent (0 new migrations)
  - Test partial failure reconciliation
  - Test missing activity store (graceful skip)

---

## User-facing migration procedure

```
1. Stop management:     systemctl stop netbird-management

2. Dry-run:             netbird-migrate-idp \
                          --config /etc/netbird/management.json \
                          --connector-id "oidc" \
                          --dry-run

3. Run migration:       netbird-migrate-idp \
                          --config /etc/netbird/management.json \
                          --connector-id "oidc"

4. Update management.json: Add EmbeddedIdP config with a StaticConnector
   whose ID matches the --connector-id used above (see below)

5. Start management:    systemctl start netbird-management
```

### Why manual config is required (step 4)

The EmbeddedIdP config block isn't just about the connector — it includes deployment-specific
values that depend on your infrastructure: OIDC issuer URL (must match your public domain),
dashboard/CLI redirect URIs (depend on your reverse proxy setup), storage paths, the initial
owner account (email + bcrypt password hash), and whether local password auth is disabled.
Auto-generating these would require the tool to make assumptions about DNS, port config,
and proxy setup that could easily be wrong. The connector ID is the only piece the migration
tool owns (it's baked into user IDs). Everything else is infrastructure config that belongs
in the operator's hands. Getting any of these wrong means management still won't start.

---

## Pitfalls and mitigations

| Risk | Mitigation |
|------|------------|
| Management running during migration | Warn user; SQLite will return SQLITE_BUSY with clear error |
| Wrong connector ID | Dry-run shows exact ID transformations; backup enables rollback |
| Partial failure mid-migration | Idempotent: `DecodeDexUserID` detects already-migrated users; reconciliation pass fixes activity store lag |
| Large user count | Each user migrated in own transaction; progress every 100 users (not per-user to avoid log spam) |
| Missing encryption key for activity store | Read from management config's `DataStoreEncryptionKey` |
| Missing activity store database | Warn and skip activity migration; main store migration proceeds |
| Empty user ID in database | Explicit guard before decode check; `DecodeDexUserID("")` succeeds with empty strings |
| Re-running with different connector-id | Already-migrated users correctly skipped (decode succeeds). To change connector-id, restore from backup first |
| MySQL store engine | Supported — existing `transaction()` helper handles `SET FOREIGN_KEY_CHECKS = 0` |
| PostgreSQL non-deferrable FK constraints | Update order (FKs first, PK last) avoids constraint violations regardless of deferrability |

---

## Verification

1. **Unit tests:** Mock-based tests for migration logic (skip/migrate/dry-run/reconcile/empty-ID guard)
2. **Integration test:** Real SQLite databases seeded with test data, verify all 13 columns
3. **Manual test:** Run `--dry-run` on a copy of a real self-hosted deployment's databases
4. **Idempotency test:** Run migration twice, second run should report 0 migrations
5. **Policy rules test:** Seed `policy_rules.authorized_user` with old user ID, verify it's updated
6. **Access log test:** Seed `access_log_entries.user_id` with old user ID, verify it's updated
7. **Missing activity store test:** Run with missing `events.db`, verify main store migration succeeds with warning

---

## Key files (all paths relative to main repo)

**New files to create:**
- `management/server/idp/migration/migration.go` — migration interfaces + `Migrate()` function
- `management/server/idp/migration/migration_test.go` — unit tests
- `management/cmd/migrate-idp/main.go` — CLI entry point
- `management/cmd/migrate-idp/backup.go` — SQLite backup logic
- `management/cmd/migrate-idp/main_test.go` — integration tests

**Existing files to modify:**
- `management/server/store/store.go` — add `ListUsers()` and `UpdateUserID()` to Store interface
- `management/server/store/sql_store.go` — add `ListUsers()`, `UpdateUserID()`, and `txDeferFKConstraints()` implementations
- `management/server/activity/store.go` — add `UpdateUserID()` to Store interface + `InMemoryEventStore.UpdateUserID()` no-op
- `management/server/activity/store/sql_store.go` — add `UpdateUserID()` implementation

**Generated files to regenerate:**
- `management/server/store/store_mock.go` — run `go generate ./management/server/store/...` after interface changes

**Read-only references (port patterns from fork):**
- Fork's `management/server/store/sql_store.go:855-895` — `UpdateUserID()` pattern
- Fork's `management/server/activity/store/sql_store.go:230-254` — activity `UpdateUserID()` pattern
- Fork's `management/server/idp/migration/migration.go` — orchestration logic pattern

**Existing files used as-is (no changes):**
- `idp/dex/provider.go` — `EncodeDexUserID` / `DecodeDexUserID`
- `management/server/types/policyrule.go:88` — `AuthorizedUser` field
- `management/internals/modules/reverseproxy/accesslogs/accesslogentry.go:25` — `AccessLogEntry.UserId` field
- `management/server/idp/embedded.go` — EmbeddedIdP manager
