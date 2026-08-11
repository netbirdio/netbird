//go:build integration

package networkmap_pgsql

import (
	"context"
	_ "embed"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	networkmap_sqlite "github.com/netbirdio/netbird/management/internals/network_map_db/sqlite"
	"github.com/netbirdio/netbird/management/server/types"
)

//go:embed base_data.sql
var baseData string

//go:embed pg_data.sql
var pgData string

//go:embed sqlite_data.sql
var sqliteData string

var (
	pgstore     *networkmap_pgsql.PgStore
	sqlitestore *networkmap_sqlite.SqliteStore
	engine      string
)

func TestMain(m *testing.M) {
	var cleanup func()
	kind, _ := os.LookupEnv("NETBIRD_STORE_ENGINE")
	switch kind {
	case string(types.PostgresStoreEngine):
		engine = string(types.PostgresStoreEngine)
		pgstore, cleanup = createPGTestStore(baseData, pgData)
	case "", string(types.SqliteStoreEngine):
		engine = string(types.SqliteStoreEngine)
		sqlitestore, cleanup = createSqliteTestStore(baseData, sqliteData)
	default:
		log.Fatalf("unsupported db '%s' in NETBIRD_STORE_ENGINE env var", kind)
	}

	code := m.Run()

	cleanup()
	os.Exit(code)
}

func conn(t *testing.T, ctx context.Context) networkmapdb.NetworkMapDBStoreConn {
	t.Helper()
	switch engine {
	case string(types.PostgresStoreEngine):
		c, err := pgstore.Pool.Acquire(ctx)
		assert.NoError(t, err)
		return pgstore.UsingConnection(c.Conn())
	case string(types.SqliteStoreEngine):
		return sqlitestore.UsingConn()
	}
	log.Fatalf("unknown db engine kind %s", engine)
	return nil
}

func execQuery(t *testing.T, ctx context.Context, q string) {
	t.Helper()
	switch engine {
	case string(types.PostgresStoreEngine):
		_, err := pgstore.Pool.Exec(ctx, q)
		assert.NoError(t, err)
	case string(types.SqliteStoreEngine):
		_, err := sqlitestore.Db.ExecContext(ctx, q)
		assert.NoError(t, err)
	}
}

// use to parse time in time.RFC3339Nano format
// returns the time in the local time zone, as that's what being returned from sql queries
// pgx returns time in the "local" timezone
// sql with sqlite driver returns time in UTC timezone
func mustParseTime(t string) *time.Time {
	tt, err := time.Parse(time.RFC3339Nano, t)
	if err != nil {
		panic(err)
	}

	if engine == string(types.SqliteStoreEngine) {
		utc := tt.UTC()
		return &utc
	}

	local := tt.Local()
	return &local
}
