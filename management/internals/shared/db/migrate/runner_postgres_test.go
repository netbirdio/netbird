package migrate

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	require.NoError(t, conn.DB(nil).Exec("CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT)").Error)

	const runners = 4
	var legacyRuns atomic.Int32
	var started sync.WaitGroup
	started.Add(runners)
	set := func() Set {
		s := testSet(map[string]string{"20260101000000_baseline.sql": baselineSQL})
		s.Legacy = func(context.Context, *gorm.DB) error {
			legacyRuns.Add(1)
			started.Wait()
			time.Sleep(500 * time.Millisecond)
			return nil
		}
		return s
	}

	replicas := replicaConns(t, dsn, runners)
	var wg sync.WaitGroup
	errs := make([]error, runners)
	for i := range runners {
		runner := newRunner(t, replicas[i], set())
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Done()
			errs[i] = runner.Run(context.Background(), ModeAuto)
		}()
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.EqualValues(t, 1, legacyRuns.Load())
	assert.Equal(t, []int64{testBaseline}, appliedVersions(t, newRunner(t, conn, set())))

	var rows int64
	require.NoError(t, conn.DB(nil).Raw("SELECT COUNT(*) FROM test_schema_migrations WHERE version_id = ?", testBaseline).Scan(&rows).Error)
	assert.EqualValues(t, 1, rows)
}
