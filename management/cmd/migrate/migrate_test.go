package migratecmd

import (
	"bytes"
	"context"
	"testing"
	"testing/fstest"

	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
)

const (
	baseline int64 = 20260101000000
	second   int64 = 20260201000000
	third    int64 = 20260301000000
)

var allFiles = map[string]string{
	"20260101000000_baseline.sql": "-- +goose Up\nCREATE TABLE things (id TEXT PRIMARY KEY);\n",
	"20260201000000_color.sql":    "-- +goose Up\nALTER TABLE things ADD COLUMN color TEXT;\n",
	"20260301000000_size.sql":     "-- +goose Up\nALTER TABLE things ADD COLUMN size TEXT;\n",
}

func testTarget(t *testing.T, name string) Target {
	t.Helper()
	return testTargetWith(t, name, allFiles)
}

func testTargetWith(t *testing.T, name string, files map[string]string) Target {
	t.Helper()
	return newTarget(t, name, files, false)
}

func testLegacyTarget(t *testing.T, name string, files map[string]string) Target {
	t.Helper()
	return newTarget(t, name, files, true)
}

func newTarget(t *testing.T, name string, files map[string]string, legacy bool) Target {
	t.Helper()
	fsys := fstest.MapFS{}
	for file, content := range files {
		fsys[migrate.SqliteDir+"/"+file] = &fstest.MapFile{Data: []byte(content)}
	}

	conn, err := db.OpenSqliteFile(context.Background(), t.TempDir(), db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	set := migrate.Set{
		Name:     name,
		Table:    name + "_schema_migrations",
		Files:    fsys,
		Baseline: baseline,
	}
	if legacy {
		require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY)").Error)
		set.LegacyTables = []string{"things"}
		set.Legacy = func(context.Context, *gorm.DB) error { return nil }
	}
	runner, err := migrate.New(conn.DB(nil), conn.Engine(), set)
	require.NoError(t, err)
	return Target{Name: name, Runner: runner, Close: func() error { return nil }}
}

func execute(t *testing.T, targets []Target, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand(func(cmd *cobra.Command, fn func(ctx context.Context, targets []Target) error) error {
		return fn(cmd.Context(), targets)
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func applied(t *testing.T, target Target) []int64 {
	t.Helper()
	statuses, err := target.Runner.Status(context.Background())
	require.NoError(t, err)
	var versions []int64
	for _, status := range statuses {
		if status.State == goose.StateApplied {
			versions = append(versions, status.Source.Version)
		}
	}
	return versions
}

func TestUp_ToStopsEveryTargetAtTheVersion(t *testing.T) {
	targets := []Target{testTarget(t, "store"), testTarget(t, "activity")}

	out, err := execute(t, targets, "up", "--to", "20260201000000")
	require.NoError(t, err)
	assert.Contains(t, out, "store: schema is current up to 20260201000000")

	for _, target := range targets {
		assert.Equal(t, []int64{baseline, second}, applied(t, target), target.Name)
	}
}

func TestUp_TargetLimitsTheDatabases(t *testing.T) {
	store, activity := testTarget(t, "store"), testTarget(t, "activity")

	_, err := execute(t, []Target{store, activity}, "up", "--target", "activity")
	require.NoError(t, err)

	assert.Empty(t, applied(t, store))
	assert.Equal(t, []int64{baseline, second, third}, applied(t, activity))
}

func TestUp_RejectsUnknownTargetAndVersion(t *testing.T) {
	store := testTarget(t, "store")

	_, err := execute(t, []Target{store}, "up", "--target", "events")
	require.ErrorContains(t, err, `unknown target "events", available: store`)

	_, err = execute(t, []Target{store}, "up", "--to", "20260201000001")
	require.ErrorContains(t, err, "version 20260201000001 is not a migration")

	assert.Empty(t, applied(t, store), "a rejected command changes nothing")
}

func TestPlan_ToShowsOnlyMigrationsUpToTheVersion(t *testing.T) {
	store := testTarget(t, "store")

	out, err := execute(t, []Target{store}, "plan", "--to", "20260201000000")
	require.NoError(t, err)

	assert.Contains(t, out, "20260101000000_baseline.sql")
	assert.Contains(t, out, "20260201000000_color.sql")
	assert.NotContains(t, out, "20260301000000_size.sql")
	assert.Empty(t, applied(t, store))
}

func TestUp_ToIsACutoffForSetsWithoutThatVersion(t *testing.T) {
	store := testTarget(t, "store")
	activity := testTargetWith(t, "activity", map[string]string{
		"20260101000000_baseline.sql": allFiles["20260101000000_baseline.sql"],
		"20260301000000_size.sql":     allFiles["20260301000000_size.sql"],
	})

	_, err := execute(t, []Target{store, activity}, "up", "--to", "20260201000000")
	require.NoError(t, err)

	assert.Equal(t, []int64{baseline, second}, applied(t, store))
	assert.Equal(t, []int64{baseline}, applied(t, activity))
}

func TestUpAndPlan_ValidateTheVersionAgainstSelectedTargetsOnly(t *testing.T) {
	store := testTarget(t, "store")
	activity := testTargetWith(t, "activity", map[string]string{
		"20260101000000_baseline.sql": allFiles["20260101000000_baseline.sql"],
	})

	for _, command := range []string{"up", "plan"} {
		_, err := execute(t, []Target{store, activity}, command, "--target", "activity", "--to", "20260201000000")
		require.ErrorContains(t, err, "version 20260201000000 is not a migration", command)
	}
	assert.Empty(t, applied(t, store))
	assert.Empty(t, applied(t, activity))
}

func TestPlan_LegacyDatabaseShowsTheBootstrapInsteadOfTheBaselineSQL(t *testing.T) {
	store := testLegacyTarget(t, "store", map[string]string{"20260101000000_baseline.sql": allFiles["20260101000000_baseline.sql"]})

	out, err := execute(t, []Target{store}, "plan")
	require.NoError(t, err)

	assert.Contains(t, out, "-- store: predates versioned migrations: the legacy bootstrap runs and baseline 20260101000000 is stamped")
	assert.NotContains(t, out, "CREATE TABLE")
	assert.NotContains(t, out, "nothing pending")
	assert.True(t, store.Runner.IsLegacy())
}

func TestPlan_LegacyDatabaseWithNewerMigrationsPrintsTheRefusal(t *testing.T) {
	store := testLegacyTarget(t, "store", allFiles)

	out, err := execute(t, []Target{store}, "plan")
	require.NoError(t, err)

	assert.Contains(t, out, "predates versioned migrations: the legacy bootstrap runs and baseline 20260101000000 is stamped")
	assert.Contains(t, out, "database predates versioned migrations; start the release that introduced them (baseline 20260101000000)")
	assert.Contains(t, out, "20260201000000_color.sql")
	assert.Contains(t, out, "20260301000000_size.sql")
	assert.NotContains(t, out, "20260101000000_baseline.sql")

	_, err = execute(t, []Target{store}, "up")
	require.ErrorContains(t, err, "database predates versioned migrations")
}
