package migrate

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
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
	set := testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
	set.Legacy = func(_ context.Context, gormDB *gorm.DB) error {
		legacyRuns++
		return gormDB.Exec("CREATE TABLE legacy_marker (id TEXT)").Error
	}
	runner := newRunner(t, conn, set)

	require.NoError(t, runner.Run(context.Background(), ModeAuto))

	assert.Equal(t, 1, legacyRuns)
	assert.True(t, conn.DB(nil).Migrator().HasTable("legacy_marker"))
	assert.Equal(t, []int64{testBaseline}, appliedVersions(t, runner))

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

	assert.Equal(t, []string{db.SqliteFileName + backupInfix + "0"}, backupNames(t, dir))

	forgetBackedUpFiles()
	files["20260201000000_color.sql"] = secondSQL
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))

	backups := backupNames(t, dir)
	require.Equal(t, []string{db.SqliteFileName + backupInfix + "20260101000000"}, backups)
	info, err := os.Stat(filepath.Join(dir, backups[0]))
	require.NoError(t, err)
	assert.Positive(t, info.Size())
}

func TestRun_SqliteBackupSurvivesFailedRunsAndRestarts(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.OpenSqliteFile(context.Background(), dir, db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	files := map[string]string{"20260101000000_baseline.sql": baselineSQL}
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))
	require.NoError(t, conn.DB(nil).Exec("INSERT INTO things (id, name) VALUES ('1', 'before')").Error)

	older := filepath.Join(dir, db.SqliteFileName+backupInfix+"1")
	require.NoError(t, os.WriteFile(older, []byte("older copy"), 0o600))

	files["20260201000000_broken.sql"] = "-- +goose Up\nALTER TABLE missing ADD COLUMN x TEXT;\n"
	broken := testSet(files)
	for range 2 {
		forgetBackedUpFiles()
		require.Error(t, newRunner(t, conn, broken).Run(context.Background(), ModeAuto))
	}

	original := filepath.Join(dir, db.SqliteFileName+backupInfix+"20260101000000")
	assert.Equal(t, "before", backupThingName(t, original))
	assert.FileExists(t, older, "a failed run must not prune older backups")

	files["20260201000000_broken.sql"] = secondSQL
	forgetBackedUpFiles()
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))
	assert.NoFileExists(t, older, "a completed run prunes older backups")
	assert.FileExists(t, original)
}

func TestRun_SqliteBackupOfSetsSharingAFileKeepsThePreRunCopy(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.OpenSqliteFile(context.Background(), dir, "shared.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)
	require.NoError(t, conn.DB(nil).Exec("INSERT INTO things VALUES ('1', 'original')").Error)
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE gadgets (id TEXT PRIMARY KEY)").Error)

	first := testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
	first.Name, first.Table = "first", "first_schema_migrations"
	first.Legacy = func(_ context.Context, gormDB *gorm.DB) error {
		return gormDB.Exec("UPDATE things SET name = 'mutated'").Error
	}
	second := testSet(map[string]string{"20260101000000_baseline.sql": "-- +goose Up\nCREATE TABLE gadgets (id TEXT PRIMARY KEY);\n"})
	second.Name, second.Table, second.LegacyTables = "second", "second_schema_migrations", []string{"gadgets"}
	second.Legacy = func(context.Context, *gorm.DB) error { return nil }

	require.NoError(t, newRunner(t, conn, first).Run(context.Background(), ModeAuto))
	require.NoError(t, newRunner(t, conn, second).Run(context.Background(), ModeAuto))

	backups := backupNames(t, dir)
	require.Len(t, backups, 1)
	assert.Equal(t, "original", backupThingName(t, filepath.Join(dir, backups[0])))
}

func TestRun_SqliteBackupPruneLeavesForeignFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data[1]*")
	require.NoError(t, os.Mkdir(dir, 0o700))
	conn, err := db.OpenSqliteFile(context.Background(), dir, db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	files := map[string]string{"20260101000000_baseline.sql": baselineSQL}
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))

	foreign := []string{
		db.SqliteFileName + backupInfix + "before-upgrade",
		db.SqliteFileName + backupInfix + "007",
		db.SqliteFileName + backupInfix + "-5",
		db.SqliteFileName + backupInfix + "1.old",
		db.SqliteFileName + ".bak",
		"other.db" + backupInfix + "1",
	}
	for _, name := range append(foreign, db.SqliteFileName+backupInfix+"1") {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600))
	}

	forgetBackedUpFiles()
	files["20260201000000_color.sql"] = secondSQL
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))

	assert.NoFileExists(t, filepath.Join(dir, db.SqliteFileName+backupInfix+"1"))
	for _, name := range foreign {
		assert.FileExists(t, filepath.Join(dir, name))
	}
	assert.FileExists(t, filepath.Join(dir, db.SqliteFileName+backupInfix+"20260101000000"))
}

func backupNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), backupInfix) {
			names = append(names, entry.Name())
		}
	}
	return names
}

func backupThingName(t *testing.T, path string) string {
	t.Helper()
	backup, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := backup.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	var name string
	require.NoError(t, backup.Raw("SELECT name FROM things WHERE id = '1'").Scan(&name).Error)
	return name
}

func forgetBackedUpFiles() {
	backedUpMu.Lock()
	defer backedUpMu.Unlock()
	clear(backedUpFiles)
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
	set := testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
	set.Legacy = func(context.Context, *gorm.DB) error {
		legacyRuns++
		return nil
	}
	runner := newRunner(t, conn, set)

	statuses, err := runner.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, goose.StatePending, statuses[0].State)
	pending, err := runner.Pending(context.Background())
	require.NoError(t, err)
	assert.Len(t, pending, 1)
	assert.False(t, conn.DB(nil).Migrator().HasTable("test_schema_migrations"))

	require.NoError(t, runner.Run(context.Background(), ModeAuto))
	assert.Equal(t, 1, legacyRuns, "the bootstrap must still run after status and plan")
	assert.Equal(t, []int64{testBaseline}, appliedVersions(t, runner))
}

func TestStatusAndPending_LeaveFreshDatabaseUntouched(t *testing.T) {
	conn := openSqlite(t)
	runner := newRunner(t, conn, testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL}))

	statuses, err := runner.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, goose.StatePending, statuses[0].State)
	pending, err := runner.Pending(context.Background())
	require.NoError(t, err)
	assert.Len(t, pending, 1)

	assert.False(t, conn.DB(nil).Migrator().HasTable("test_schema_migrations"))
	require.ErrorContains(t, runner.Run(context.Background(), ModeCheck), "no version table, run `migrate up` first")
}

func threeVersionFiles() map[string]string {
	return map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260201000000_color.sql":    secondSQL,
		"20260301000000_other.sql":    thirdSQL,
	}
}

func TestUpTo_StopsAtTheTargetVersion(t *testing.T) {
	conn := openSqlite(t)
	runner := newRunner(t, conn, testSet(threeVersionFiles()))

	require.NoError(t, runner.UpTo(context.Background(), testSecond))

	assert.Equal(t, []int64{testBaseline, testSecond}, appliedVersions(t, runner))
	assert.True(t, conn.DB(nil).Migrator().HasColumn("things", "color"))
	assert.False(t, conn.DB(nil).Migrator().HasTable("other_things"))

	pending, err := runner.Pending(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, testThird, pending[0].Version)

	require.NoError(t, runner.UpTo(context.Background(), testSecond), "a second run up to the same version is a no-op")
	require.NoError(t, runner.Run(context.Background(), ModeAuto))
	assert.Equal(t, []int64{testBaseline, testSecond, testThird}, appliedVersions(t, runner))
}

func TestUpTo_AppliesOlderVersionsMergedOutOfOrder(t *testing.T) {
	conn := openSqlite(t)
	files := map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260301000000_other.sql":    thirdSQL,
	}
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))

	runner := newRunner(t, conn, testSet(threeVersionFiles()))
	require.NoError(t, runner.UpTo(context.Background(), testSecond))

	assert.Equal(t, []int64{testBaseline, testSecond, testThird}, appliedVersions(t, runner))
}

func TestUpTo_LeavesOlderMissingVersionsAboveTheTarget(t *testing.T) {
	conn := openSqlite(t)
	files := map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260301000000_other.sql":    thirdSQL,
	}
	require.NoError(t, newRunner(t, conn, testSet(files)).Run(context.Background(), ModeAuto))

	runner := newRunner(t, conn, testSet(threeVersionFiles()))
	require.NoError(t, runner.UpTo(context.Background(), testBaseline))

	assert.Equal(t, []int64{testBaseline, testThird}, appliedVersions(t, runner))
	assert.False(t, conn.DB(nil).Migrator().HasColumn("things", "color"))
}

func TestUpTo_LegacyDatabaseRunsBootstrapFirst(t *testing.T) {
	conn := openSqlite(t)
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)
	legacyRuns := 0
	set := testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
	set.Legacy = func(context.Context, *gorm.DB) error {
		legacyRuns++
		return nil
	}
	runner := newRunner(t, conn, set)

	require.NoError(t, runner.UpTo(context.Background(), testBaseline))

	assert.Equal(t, 1, legacyRuns)
	assert.Equal(t, []int64{testBaseline}, appliedVersions(t, runner))

	backups, err := filepath.Glob(filepath.Join(filepath.Dir(sqliteFile(t, conn)), db.SqliteFileName+backupInfix+"*"))
	require.NoError(t, err)
	assert.Len(t, backups, 1, "a legacy database is backed up before the bootstrap")
}

func TestUpTo_RejectsInvalidVersion(t *testing.T) {
	runner := newRunner(t, openSqlite(t), testSet(threeVersionFiles()))
	require.Error(t, runner.UpTo(context.Background(), 0))
	assert.Empty(t, appliedVersions(t, runner))
}

func TestPendingUpTo_FiltersLaterVersions(t *testing.T) {
	runner := newRunner(t, openSqlite(t), testSet(threeVersionFiles()))

	pending, err := runner.PendingUpTo(context.Background(), testSecond)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assert.Equal(t, testBaseline, pending[0].Version)
	assert.Equal(t, testSecond, pending[1].Version)
}

func TestHasVersion(t *testing.T) {
	runner := newRunner(t, openSqlite(t), testSet(threeVersionFiles()))
	assert.True(t, runner.HasVersion(testSecond))
	assert.False(t, runner.HasVersion(testSecond+1))
}

func legacyConn(t *testing.T) (*db.Conn, string) {
	t.Helper()
	dir := t.TempDir()
	conn, err := db.OpenSqliteFile(context.Background(), dir, db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)
	return conn, dir
}

func TestRun_LegacyDatabaseWithMigrationsAboveBaselineIsRefusedUntouched(t *testing.T) {
	conn, dir := legacyConn(t)
	legacyRuns := 0
	set := testSet(threeVersionFiles())
	set.Legacy = func(context.Context, *gorm.DB) error {
		legacyRuns++
		return nil
	}
	runner := newRunner(t, conn, set)

	for name, run := range map[string]func() error{
		"auto":  func() error { return runner.Run(context.Background(), ModeAuto) },
		"check": func() error { return runner.Run(context.Background(), ModeCheck) },
		"upto":  func() error { return runner.UpTo(context.Background(), testBaseline) },
	} {
		err := run()
		require.ErrorContains(t, err, "database predates versioned migrations", name)
		require.ErrorContains(t, err, "baseline 20260101000000", name)
	}

	assert.Zero(t, legacyRuns)
	assert.False(t, conn.DB(nil).Migrator().HasTable("test_schema_migrations"))
	assert.Empty(t, backupNames(t, dir))
	assert.True(t, runner.IsLegacy())
	assert.Equal(t, testBaseline, runner.Baseline())
}

func TestRun_LegacyDatabaseWithGoMigrationAboveBaselineIsRefused(t *testing.T) {
	conn, _ := legacyConn(t)
	set := testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
	set.Go = []*goose.Migration{goose.NewGoMigration(testSecond, &goose.GoFunc{RunTx: func(context.Context, *sql.Tx) error { return nil }}, nil)}
	set.Legacy = func(context.Context, *gorm.DB) error { return nil }

	require.ErrorContains(t, newRunner(t, conn, set).Run(context.Background(), ModeAuto), "database predates versioned migrations")
	assert.False(t, conn.DB(nil).Migrator().HasTable("test_schema_migrations"))
}

func TestCheckLegacy_AllowsFreshAndVersionedDatabases(t *testing.T) {
	fresh := newRunner(t, openSqlite(t), testSet(threeVersionFiles()))
	assert.NoError(t, fresh.CheckLegacy())
	assert.False(t, fresh.IsLegacy())

	conn := openSqlite(t)
	versioned := newRunner(t, conn, testSet(threeVersionFiles()))
	require.NoError(t, versioned.Run(context.Background(), ModeAuto))
	assert.NoError(t, versioned.CheckLegacy())
}

func TestNew_RejectsNonTransactionalGoMigration(t *testing.T) {
	set := testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
	set.Go = []*goose.Migration{goose.NewGoMigration(testSecond, &goose.GoFunc{RunDB: func(context.Context, *sql.DB) error { return nil }}, nil)}

	_, err := New(openSqlite(t).DB(nil), db.SqliteStoreEngine, set)
	require.ErrorContains(t, err, "must use RunTx")
}

func TestNew_RejectsMigrationsBelowTheBaseline(t *testing.T) {
	conn := openSqlite(t)
	set := testSet(map[string]string{
		"20251201000000_early.sql":    thirdSQL,
		"20260101000000_baseline.sql": baselineSQL,
	})
	_, err := New(conn.DB(nil), db.SqliteStoreEngine, set)
	require.ErrorContains(t, err, "below the baseline")

	set = testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
	set.Go = []*goose.Migration{goose.NewGoMigration(testBaseline-1, &goose.GoFunc{RunTx: func(context.Context, *sql.Tx) error { return nil }}, nil)}
	_, err = New(conn.DB(nil), db.SqliteStoreEngine, set)
	require.ErrorContains(t, err, "below the baseline")
}
