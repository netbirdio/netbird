# Activity store migrations

Versioned schema migrations of the activity event store, applied by
`internals/shared/db/migrate` through goose. The conventions are those of the
management store, see `management/server/store/migrations/README.md`; the
version table is `activity_schema_migrations`, so the set can share a Postgres
database with the management store.

`20260930120000_baseline.sql` is the schema the legacy path (hand-written
migrations plus gorm AutoMigrate) produced on an empty database when versioning
started, captured by recording the DDL that path executed. It is never edited.
