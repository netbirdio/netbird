package migrate

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

const (
	testBaseline int64 = 20260101000000
	testSecond   int64 = 20260201000000
	testThird    int64 = 20260301000000
)

const baselineSQL = `-- +goose Up
CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT);
`

const secondSQL = `-- +goose Up
ALTER TABLE things ADD COLUMN color TEXT;
`

const thirdSQL = `-- +goose Up
CREATE TABLE other_things (id TEXT PRIMARY KEY);
`

// testFiles builds a set directory with the same files for both engines.
func testFiles(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, content := range files {
		fsys[PostgresDir+"/"+name] = &fstest.MapFile{Data: []byte(content)}
		fsys[SqliteDir+"/"+name] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

func testSet(files map[string]string) Set {
	return Set{
		Name:         "test",
		Table:        "test_schema_migrations",
		Files:        testFiles(files),
		Baseline:     testBaseline,
		LegacyTables: []string{"things"},
	}
}

func openSqlite(t *testing.T) *db.Conn {
	t.Helper()
	conn, err := db.OpenSqliteFile(context.Background(), t.TempDir(), db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newRunner(t *testing.T, conn *db.Conn, set Set) *Runner {
	t.Helper()
	runner, err := New(conn.DB(nil), conn.Engine(), set)
	require.NoError(t, err)
	return runner
}

func appliedVersions(t *testing.T, runner *Runner) []int64 {
	t.Helper()
	statuses, err := runner.Status(context.Background())
	require.NoError(t, err)
	var applied []int64
	for _, status := range statuses {
		if status.State == goose.StateApplied {
			applied = append(applied, status.Source.Version)
		}
	}
	return applied
}

func TestParseMode(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  Mode
	}{
		{"", ModeAuto},
		{"auto", ModeAuto},
		{" Check ", ModeCheck},
		{"SKIP", ModeSkip},
	} {
		mode, err := ParseMode(tc.value)
		require.NoError(t, err, tc.value)
		assert.Equal(t, tc.want, mode, tc.value)
	}

	_, err := ParseMode("later")
	require.Error(t, err)
}

func TestResolveMode_EnvOverridesConfig(t *testing.T) {
	t.Setenv(ModeEnv, "check")
	mode, err := ResolveMode("skip")
	require.NoError(t, err)
	assert.Equal(t, ModeCheck, mode)

	t.Setenv(ModeEnv, "")
	mode, err = ResolveMode("skip")
	require.NoError(t, err)
	assert.Equal(t, ModeSkip, mode)
}

func TestNew_RejectsUnsupportedEngine(t *testing.T) {
	conn := openSqlite(t)
	_, err := New(conn.DB(nil), db.Engine("mysql"), testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL}))
	require.ErrorContains(t, err, "not supported")
}

func TestRun_FreshDatabaseAppliesEverything(t *testing.T) {
	conn := openSqlite(t)
	set := testSet(map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260201000000_color.sql":    secondSQL,
	})
	runner := newRunner(t, conn, set)

	require.NoError(t, runner.Run(context.Background(), ModeAuto))

	migrator := conn.DB(nil).Migrator()
	assert.True(t, migrator.HasTable("things"))
	assert.True(t, migrator.HasColumn("things", "color"))
	assert.Equal(t, []int64{testBaseline, testSecond}, appliedVersions(t, runner))

	pending, err := runner.Pending(context.Background())
	require.NoError(t, err)
	assert.Empty(t, pending)
	require.NoError(t, runner.Run(context.Background(), ModeAuto))

	backups, err := filepath.Glob(filepath.Join(filepath.Dir(sqliteFile(t, conn)), db.SqliteFileName+backupInfix+"*"))
	require.NoError(t, err)
	assert.Empty(t, backups, "an empty database is not backed up")
}

func sqliteFile(t *testing.T, conn *db.Conn) string {
	t.Helper()
	var file string
	require.NoError(t, conn.DB(nil).Raw("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&file).Error)
	return file
}

func TestRun_LegacyDatabaseRunsBootstrapAndStampsBaseline(t *testing.T) {
	conn := openSqlite(t)
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)

	legacyRuns := 0
	set := testSet(map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260201000000_color.sql":    secondSQL,
	})
	set.Legacy = func(_ context.Context, gormDB *gorm.DB) error {
		legacyRuns++
		return gormDB.Exec("CREATE TABLE legacy_marker (id TEXT)").Error
	}
	runner := newRunner(t, conn, set)

	require.NoError(t, runner.Run(context.Background(), ModeAuto))

	assert.Equal(t, 1, legacyRuns)
	migrator := conn.DB(nil).Migrator()
	assert.True(t, migrator.HasTable("legacy_marker"))
	assert.True(t, migrator.HasColumn("things", "color"))
	assert.Equal(t, []int64{testBaseline, testSecond}, appliedVersions(t, runner))

	require.NoError(t, runner.Run(context.Background(), ModeAuto))
	assert.Equal(t, 1, legacyRuns)
}

func TestRun_LegacyDatabaseWithoutBootstrapFailsOnBaseline(t *testing.T) {
	conn := openSqlite(t)
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)
	runner := newRunner(t, conn, testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL}))

	require.Error(t, runner.Run(context.Background(), ModeAuto))
}

func TestRun_CheckMode(t *testing.T) {
	conn := openSqlite(t)
	files := map[string]string{"20260101000000_baseline.sql": baselineSQL}
	runner := newRunner(t, conn, testSet(files))

	require.ErrorContains(t, runner.Run(context.Background(), ModeCheck), "no version table")
	assert.False(t, conn.DB(nil).Migrator().HasTable("things"))

	require.NoError(t, runner.Run(context.Background(), ModeAuto))
	require.NoError(t, runner.Run(context.Background(), ModeCheck))

	files["20260201000000_color.sql"] = secondSQL
	newer := newRunner(t, conn, testSet(files))
	require.ErrorContains(t, newer.Run(context.Background(), ModeCheck), "pending")
	assert.False(t, conn.DB(nil).Migrator().HasColumn("things", "color"))
}

func TestRun_SkipModeTouchesNothing(t *testing.T) {
	conn := openSqlite(t)
	runner := newRunner(t, conn, testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL}))

	require.NoError(t, runner.Run(context.Background(), ModeSkip))

	assert.False(t, conn.DB(nil).Migrator().HasTable("things"))
	assert.False(t, conn.DB(nil).Migrator().HasTable("test_schema_migrations"))
}

func TestRun_AppliesVersionsMergedOutOfOrder(t *testing.T) {
	conn := openSqlite(t)
	files := map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260301000000_other.sql":    thirdSQL,
	}
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))

	files["20260201000000_color.sql"] = secondSQL
	runner := newRunner(t, conn, testSet(files))
	require.NoError(t, runner.Run(context.Background(), ModeAuto))

	assert.True(t, conn.DB(nil).Migrator().HasColumn("things", "color"))
	assert.Equal(t, []int64{testBaseline, testSecond, testThird}, appliedVersions(t, runner))
}

func TestRun_ToleratesVersionsNewerThanTheBinary(t *testing.T) {
	conn := openSqlite(t)
	files := map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260201000000_color.sql":    secondSQL,
	}
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))

	older := newRunner(t, conn, testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL}))
	require.NoError(t, older.Run(context.Background(), ModeAuto))
	require.NoError(t, older.Run(context.Background(), ModeCheck))
}

func TestPending_ReturnsSQLOfPendingFiles(t *testing.T) {
	conn := openSqlite(t)
	runner := newRunner(t, conn, testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL}))

	pending, err := runner.Pending(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, testBaseline, pending[0].Version)
	assert.Equal(t, goose.TypeSQL, pending[0].Type)
	assert.Equal(t, baselineSQL, pending[0].SQL)
	assert.False(t, conn.DB(nil).Migrator().HasTable("things"))
}

func TestRun_SqliteBackupKeepsOnlyTheNewestCopy(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.OpenSqliteFile(context.Background(), dir, db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)

	files := map[string]string{"20260101000000_baseline.sql": baselineSQL}
	set := testSet(files)
	set.Legacy = func(context.Context, *gorm.DB) error { return nil }
	require.NoError(t, newRunner(t, conn, set).Run(context.Background(), ModeAuto))

	backups, err := filepath.Glob(filepath.Join(dir, db.SqliteFileName+backupInfix+"*"))
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(dir, db.SqliteFileName+backupInfix+"0")}, backups)

	files["20260201000000_color.sql"] = secondSQL
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))

	backups, err = filepath.Glob(filepath.Join(dir, db.SqliteFileName+backupInfix+"*"))
	require.NoError(t, err)
	require.Len(t, backups, 1)
	assert.Equal(t, filepath.Join(dir, db.SqliteFileName+backupInfix+"20260101000000"), backups[0])
	info, err := os.Stat(backups[0])
	require.NoError(t, err)
	assert.Positive(t, info.Size())
}

func TestRun_GoMigrationsShareTheSequence(t *testing.T) {
	conn := openSqlite(t)
	set := testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
	set.Go = []*goose.Migration{
		goose.NewGoMigration(testSecond, &goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO things (id, name) VALUES ('a', 'seeded')")
			return err
		}}, nil),
	}
	runner := newRunner(t, conn, set)

	require.NoError(t, runner.Run(context.Background(), ModeAuto))

	var count int64
	require.NoError(t, conn.DB(nil).Raw("SELECT COUNT(*) FROM things").Scan(&count).Error)
	assert.EqualValues(t, 1, count)
	assert.Equal(t, []int64{testBaseline, testSecond}, appliedVersions(t, runner))
}

func TestRun_FailedLegacyBootstrapRetriesOnNextStart(t *testing.T) {
	conn := openSqlite(t)
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)

	files := map[string]string{"20260101000000_baseline.sql": baselineSQL}
	failing := testSet(files)
	failing.Legacy = func(context.Context, *gorm.DB) error { return assert.AnError }
	require.ErrorIs(t, newRunner(t, conn, failing).Run(context.Background(), ModeAuto), assert.AnError)
	assert.False(t, conn.DB(nil).Migrator().HasTable("test_schema_migrations"), "a failed bootstrap must not leave a version table behind")

	legacyRuns := 0
	working := testSet(files)
	working.Legacy = func(context.Context, *gorm.DB) error {
		legacyRuns++
		return nil
	}
	runner := newRunner(t, conn, working)
	require.NoError(t, runner.Run(context.Background(), ModeAuto))
	assert.Equal(t, 1, legacyRuns)
	assert.Equal(t, []int64{testBaseline}, appliedVersions(t, runner))
}

func TestStatusAndPending_LeaveLegacyDatabaseUntouched(t *testing.T) {
	conn := openSqlite(t)
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)

	legacyRuns := 0
	set := testSet(map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260201000000_color.sql":    secondSQL,
	})
	set.Legacy = func(context.Context, *gorm.DB) error {
		legacyRuns++
		return nil
	}
	runner := newRunner(t, conn, set)

	statuses, err := runner.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, statuses, 2)
	for _, status := range statuses {
		assert.Equal(t, goose.StatePending, status.State)
	}
	pending, err := runner.Pending(context.Background())
	require.NoError(t, err)
	assert.Len(t, pending, 2)
	assert.False(t, conn.DB(nil).Migrator().HasTable("test_schema_migrations"))

	require.NoError(t, runner.Run(context.Background(), ModeAuto))
	assert.Equal(t, 1, legacyRuns, "the bootstrap must still run after status and plan")
	assert.Equal(t, []int64{testBaseline, testSecond}, appliedVersions(t, runner))
}
