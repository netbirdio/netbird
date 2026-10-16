package migrate

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/testutil"
)

func postgresDSN(t *testing.T) string {
	t.Helper()
	if os.Getenv("NETBIRD_STORE_ENGINE") != string(db.PostgresStoreEngine) {
		t.Skip("NETBIRD_STORE_ENGINE is not postgres")
	}
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)
	return dsn
}

func openPostgres(t *testing.T, dsn string) *db.Conn {
	t.Helper()
	conn, err := db.OpenPostgres(context.Background(), dsn, db.DefaultPoolConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// replicaConns opens one connection pool per simulated management instance.
func replicaConns(t *testing.T, dsn string, n int) []*db.Conn {
	t.Helper()
	conns := make([]*db.Conn, n)
	for i := range conns {
		conns[i] = openPostgres(t, dsn)
	}
	return conns
}

func TestRun_Postgres_ConcurrentRunnersApplyOnce(t *testing.T) {
	dsn := postgresDSN(t)
	conn := openPostgres(t, dsn)
	files := map[string]string{
		"20260101000000_baseline.sql": baselineSQL,
		"20260201000000_color.sql":    secondSQL,
	}

	const runners = 4
	replicas := replicaConns(t, dsn, runners)
	var wg sync.WaitGroup
	errs := make([]error, runners)
	for i := range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = newRunner(t, replicas[i], testSet(files)).Run(context.Background(), ModeAuto)
		}()
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.True(t, conn.DB(nil).Migrator().HasColumn("things", "color"))
	assert.Equal(t, []int64{testBaseline, testSecond}, appliedVersions(t, newRunner(t, conn, testSet(files))))

	var rows int64
	require.NoError(t, conn.DB(nil).Raw("SELECT COUNT(*) FROM test_schema_migrations WHERE version_id = ?", testBaseline).Scan(&rows).Error)
	assert.EqualValues(t, 1, rows)
}

func TestRun_Postgres_LegacyDatabaseIsStampedOnce(t *testing.T) {
	dsn := postgresDSN(t)
	conn := openPostgres(t, dsn)
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)

	files := map[string]string{"20260101000000_baseline.sql": baselineSQL}
	var legacyRuns sync.Map
	set := func() Set {
		s := testSet(files)
		s.Legacy = func(context.Context, *gorm.DB) error {
			legacyRuns.Store(struct{}{}, true)
			return nil
		}
		return s
	}

	const runners = 3
	replicas := replicaConns(t, dsn, runners)
	var wg sync.WaitGroup
	errs := make([]error, runners)
	for i := range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = newRunner(t, replicas[i], set()).Run(context.Background(), ModeAuto)
		}()
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	var rows int64
	require.NoError(t, conn.DB(nil).Raw("SELECT COUNT(*) FROM test_schema_migrations WHERE version_id = ?", testBaseline).Scan(&rows).Error)
	assert.EqualValues(t, 1, rows)
}
