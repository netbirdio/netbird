# Management store migrations

Versioned schema migrations of the management store, applied by
`internals/shared/db/migrate` through goose. `postgres/` and `sqlite/` hold the
SQL files of the respective engine; Go migrations live next to
`../migrations.go` and share the version sequence.

## Writing a migration

- The version is the UTC timestamp `YYYYMMDDHHMMSS` of the moment the file is
  created. Both engine directories get a file with that version, an empty
  `-- +goose Up` block when one engine needs nothing.
- Every file starts with `-- +goose Up`. Postgres files continue with
  `SET LOCAL lock_timeout = '5s';` so a DDL statement waiting behind a long
  transaction fails and is retried instead of queueing every other query.
- A migration runs in one transaction. `CREATE INDEX CONCURRENTLY` needs
  `-- +goose NO TRANSACTION` at the top of the file.
- Go migrations use `goose.GoFunc.RunTx`, never `RunDB`: goose holds the pool's
  only SQLite connection while it runs, so a function that needs a second
  connection deadlocks.
- The schema of release N must work with the binary of release N-1, because
  both run during a rollout and a rollback redeploys N-1. Add columns and
  tables in one release; drop, rename or tighten them one release later, after
  no code reads the old shape.
- Row-heavy backfills do not belong in a migration. They run after startup in
  batches, see the design notes in the runner package.
- `TestMigrationsMatchAutoMigrate` compares the schema the migrations produce
  with the schema gorm derives from the models; a model change without a
  migration fails it.

## Baseline

`20260930120000_baseline.sql` is the schema the legacy path (pre-migrations,
gorm AutoMigrate, post-migrations) produced on an empty database at the time
versioning started. It was captured by recording every DDL statement that path
executed and is never edited. Databases created before it run the legacy path
once and are stamped at the baseline.
