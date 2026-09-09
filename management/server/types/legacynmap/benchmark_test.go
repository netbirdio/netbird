//go:build nmapequiv

// Account-load benchmark: the legacy store.GetAccount hydration (pgx fast
// path, as in production) vs the nmdata store's GetNetworkMapData, against the
// same Postgres copy as the equivalence test.
//
//	NETBIRD_STORE_ENGINE_POSTGRES_DSN='...' go test -tags nmapequiv \
//	  -run '^$' -bench . -benchtime 5x -timeout 60m \
//	  ./management/server/types/legacynmap/
//
// NETMAP_ACCOUNTS selects the accounts (comma-separated); by default the ten
// accounts with the most peers are used. Each account is a sub-benchmark, so
// the two paths can be compared per account. One warmup call runs untimed
// before each measurement so Postgres buffer-cache state is comparable.
//
// Reported metrics beyond ns/op and allocs:
//
//   - queries/op    round trips, counted client-side via a pgx tracer
//     (GetNetworkMapData only — the legacy store's pool is internal)
//   - xact/op       committed transactions from pg_stat_database; the legacy
//     pgx path runs autocommit statements, so this approximates its round
//     trips, while GetNetworkMapData runs a single transaction
//   - tup_returned/op, tup_fetched/op   rows scanned/fetched server-side
//   - blks_read/op, blks_hit/op         buffer cache misses/hits
//
// The pg_stat_database numbers are database-global: run without concurrent
// load. The two stat snapshots per sub-benchmark add a small constant
// overhead to the server-side deltas.
package legacynmap_test

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

func BenchmarkGetAccount(b *testing.B) {
	dsn := equivDSN()
	if dsn == "" {
		b.Skip("NETBIRD_STORE_ENGINE_POSTGRES_DSN not set")
	}
	ctx := context.Background()

	statsConn, err := pgx.Connect(ctx, dsn)
	require.NoError(b, err, "connect stats connection")
	b.Cleanup(func() { statsConn.Close(ctx) })

	testStore, err := store.NewPostgresqlStore(ctx, dsn, nil, true)
	require.NoError(b, err, "connect to postgres")
	b.Cleanup(func() { testStore.Close(ctx) })

	for _, accountID := range benchAccountIDs(b, ctx, statsConn) {
		b.Run(accountID, func(b *testing.B) {
			logAccountShape(b, ctx, statsConn, accountID)
			benchDBLoad(b, ctx, statsConn, nil, func() error {
				_, err := testStore.GetAccount(ctx, accountID)
				return err
			})
		})
	}
}

func BenchmarkGetNetworkMapData(b *testing.B) {
	dsn := equivDSN()
	if dsn == "" {
		b.Skip("NETBIRD_STORE_ENGINE_POSTGRES_DSN not set")
	}
	ctx := context.Background()

	statsConn, err := pgx.Connect(ctx, dsn)
	require.NoError(b, err, "connect stats connection")
	b.Cleanup(func() { statsConn.Close(ctx) })

	tracer := &queryCountTracer{}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(b, err, "parse dsn")
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(b, err, "connect nmdata store")
	b.Cleanup(pool.Close)
	nmStore := nmDataStore(b, &networkmap_pgsql.PgStore{Pool: pool})

	for _, accountID := range benchAccountIDs(b, ctx, statsConn) {
		b.Run(accountID, func(b *testing.B) {
			logAccountShape(b, ctx, statsConn, accountID)
			benchDBLoad(b, ctx, statsConn, tracer, func() error {
				_, err := nmStore.GetNetworkMapData(ctx, accountID)
				return err
			})
		})
	}
}

// BenchmarkAccountFullRound measures store load plus the full per-peer fan-out
// to *proto.SyncResponse for every peer of the account, the way the production
// account path runs it: index maps and per-peer twin building happen after
// GetAccount and are part of the measured op. BenchmarkNetworkMapDataFullRound
// is the equivalent for the nmdata path, whose index building happens inside
// GetNetworkMapData. Select both with -bench FullRound.
func BenchmarkAccountFullRound(b *testing.B) {
	dsn := equivDSN()
	if dsn == "" {
		b.Skip("NETBIRD_STORE_ENGINE_POSTGRES_DSN not set")
	}
	ctx := context.Background()

	statsConn, err := pgx.Connect(ctx, dsn)
	require.NoError(b, err, "connect stats connection")
	b.Cleanup(func() { statsConn.Close(ctx) })

	testStore, err := store.NewPostgresqlStore(ctx, dsn, nil, true)
	require.NoError(b, err, "connect to postgres")
	b.Cleanup(func() { testStore.Close(ctx) })

	for _, accountID := range benchAccountIDs(b, ctx, statsConn) {
		b.Run(accountID, func(b *testing.B) {
			logAccountShape(b, ctx, statsConn, accountID)
			benchDBLoad(b, ctx, statsConn, nil, func() error {
				account, err := testStore.GetAccount(ctx, accountID)
				if err != nil {
					return err
				}
				buildAccountSyncResponses(ctx, account)
				return nil
			})
		})
	}
}

func BenchmarkNetworkMapDataFullRound(b *testing.B) {
	dsn := equivDSN()
	if dsn == "" {
		b.Skip("NETBIRD_STORE_ENGINE_POSTGRES_DSN not set")
	}
	ctx := context.Background()

	statsConn, err := pgx.Connect(ctx, dsn)
	require.NoError(b, err, "connect stats connection")
	b.Cleanup(func() { statsConn.Close(ctx) })

	tracer := &queryCountTracer{}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(b, err, "parse dsn")
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(b, err, "connect nmdata store")
	b.Cleanup(pool.Close)
	nmStore := nmDataStore(b, &networkmap_pgsql.PgStore{Pool: pool})

	for _, accountID := range benchAccountIDs(b, ctx, statsConn) {
		b.Run(accountID, func(b *testing.B) {
			logAccountShape(b, ctx, statsConn, accountID)
			benchDBLoad(b, ctx, statsConn, tracer, func() error {
				nmData, err := nmStore.GetNetworkMapData(ctx, accountID)
				if err != nil {
					return err
				}
				buildDataSyncResponses(ctx, nmData)
				return nil
			})
		})
	}
}

// buildAccountSyncResponses fans out to every peer like the controller's
// account path: index maps once, twin conversion and network-map computation
// per peer.
func buildAccountSyncResponses(ctx context.Context, account *types.Account) {
	validated := make(map[string]struct{}, len(account.Peers))
	for peerID := range account.Peers {
		validated[peerID] = struct{}{}
	}
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupUsers := account.GetActiveGroupUsers()
	settings := account.Settings
	if settings == nil {
		settings = &types.Settings{}
	}
	dnsCache := &cache.DNSConfigCache{}

	for peerID, peer := range account.Peers {
		nm := account.GetPeerNetworkMapFromComponents(
			ctx, peerID, nbdns.CustomZone{}, nil, validated, resourcePolicies, routers, nil, groupUsers,
		)
		mgmtgrpc.ToSyncResponse(
			ctx, nil, nil, nil, types.TwinPeer(peer), nil, nil, nm, equivDNSName, nil,
			dnsCache, types.TwinAccountSettings(settings), settings.Extra, nil, 0,
		)
	}
}

// buildDataSyncResponses is the nmdata-path equivalent of
// buildAccountSyncResponses.
func buildDataSyncResponses(ctx context.Context, nmData *networkmap.NetworkMapData) {
	validated := make(map[string]struct{}, len(nmData.Peers))
	for peerID := range nmData.Peers {
		validated[peerID] = struct{}{}
	}
	nmData.ValidatedPeers = validated
	dnsCache := &cache.DNSConfigCache{}

	for peerID, peer := range nmData.Peers {
		components := nmData.GetPeerNetworkMapComponents(peerID, nmdata.CustomZone{})
		nm := &types.NetworkMap{Network: components.Network}
		if !components.IsEmpty() {
			nm = types.CalculateNetworkMapFromComponents(ctx, components)
		}
		mgmtgrpc.ToSyncResponse(
			ctx, nil, nil, nil, peer, nil, nil, nm, equivDNSName, nil,
			dnsCache, nmData.AccountSettings, nil, nil, 0,
		)
	}
}

// benchDBLoad runs op b.N times and reports server-side pg_stat_database
// deltas per op. A non-nil tracer additionally reports exact client round
// trips per op.
//
// Backends flush cumulative stats at most once per second and only while
// processing commands, so around each snapshot the load settles: sleep past
// the flush interval, then run one extra untimed op whose command end flushes
// everything pending. The trailing extra op lands inside the measured window,
// hence the b.N+1 denominator for the server-side metrics.
func benchDBLoad(b *testing.B, ctx context.Context, statsConn *pgx.Conn, tracer *queryCountTracer, op func() error) {
	b.Helper()

	require.NoError(b, op(), "warmup")
	settleDBStats(b, op)

	before, err := snapshotDBStats(ctx, statsConn)
	require.NoError(b, err, "stats snapshot")
	var queriesBefore int64
	if tracer != nil {
		queriesBefore = tracer.queries.Load()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := op(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	settleDBStats(b, op)
	after, err := snapshotDBStats(ctx, statsConn)
	require.NoError(b, err, "stats snapshot")

	ops := float64(b.N + 1)
	if tracer != nil {
		b.ReportMetric(float64(tracer.queries.Load()-queriesBefore)/ops, "queries/op")
	}
	b.ReportMetric(float64(after.xactCommit-before.xactCommit)/ops, "xact/op")
	b.ReportMetric(float64(after.tupReturned-before.tupReturned)/ops, "tup_returned/op")
	b.ReportMetric(float64(after.tupFetched-before.tupFetched)/ops, "tup_fetched/op")
	b.ReportMetric(float64(after.blksRead-before.blksRead)/ops, "blks_read/op")
	b.ReportMetric(float64(after.blksHit-before.blksHit)/ops, "blks_hit/op")
}

func settleDBStats(b *testing.B, op func() error) {
	b.Helper()
	time.Sleep(1100 * time.Millisecond)
	require.NoError(b, op(), "stats flush op")
	time.Sleep(100 * time.Millisecond)
}

func benchAccountIDs(b *testing.B, ctx context.Context, conn *pgx.Conn) []string {
	b.Helper()

	if ids := strings.TrimSpace(os.Getenv("NETMAP_ACCOUNTS")); ids != "" {
		var out []string
		for _, id := range strings.Split(ids, ",") {
			if id = strings.TrimSpace(id); id != "" {
				out = append(out, id)
			}
		}
		return out
	}

	rows, err := conn.Query(ctx,
		"select account_id from peers group by account_id order by count(*) desc, account_id limit 10")
	require.NoError(b, err, "list benchmark accounts")
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(b, err, "collect benchmark accounts")
	require.NotEmpty(b, ids, "no accounts found")
	return ids
}

func logAccountShape(b *testing.B, ctx context.Context, conn *pgx.Conn, accountID string) {
	b.Helper()

	var peers, groups, users, policies, routes, resources, nsGroups int
	err := conn.QueryRow(ctx, `select
		(select count(*) from peers where account_id=$1),
		(select count(*) from groups where account_id=$1),
		(select count(*) from users where account_id=$1),
		(select count(*) from policies where account_id=$1),
		(select count(*) from routes where account_id=$1),
		(select count(*) from network_resources where account_id=$1),
		(select count(*) from name_server_groups where account_id=$1)`, accountID).
		Scan(&peers, &groups, &users, &policies, &routes, &resources, &nsGroups)
	require.NoError(b, err, "account shape")
	b.Logf("account=%s peers=%d groups=%d users=%d policies=%d routes=%d resources=%d nsgroups=%d",
		accountID, peers, groups, users, policies, routes, resources, nsGroups)
}

type dbStats struct {
	xactCommit  int64
	tupReturned int64
	tupFetched  int64
	blksRead    int64
	blksHit     int64
}

func snapshotDBStats(ctx context.Context, conn *pgx.Conn) (dbStats, error) {
	var s dbStats
	err := conn.QueryRow(ctx, `select xact_commit, tup_returned, tup_fetched, blks_read, blks_hit
		from pg_stat_database where datname = current_database()`).
		Scan(&s.xactCommit, &s.tupReturned, &s.tupFetched, &s.blksRead, &s.blksHit)
	return s, err
}

type queryCountTracer struct {
	queries atomic.Int64
}

func (t *queryCountTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	t.queries.Add(1)
	return ctx
}

func (t *queryCountTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
