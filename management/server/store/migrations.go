package store

import (
	"context"
	"embed"
	"fmt"

	"gorm.io/gorm"

	nbdns "github.com/netbirdio/netbird/dns"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

//go:embed migrations
var migrationFiles embed.FS

const (
	// MigrationTable records the applied versions of the management store.
	MigrationTable = "schema_migrations"
	// baselineVersion creates the schema the legacy path produced when versioning started.
	baselineVersion int64 = 20260930120000
)

// MigrationSet returns the versioned migrations of the management store.
func MigrationSet() migrate.Set {
	files := migrate.Dir(migrationFiles, "migrations")
	return migrate.Set{
		Name:         "store",
		Table:        MigrationTable,
		Files:        files,
		Baseline:     baselineVersion,
		LegacyTables: []string{"accounts", "peers"},
		Legacy:       legacyMigrate,
	}
}

// NewMigrationRunner opens the configured database and returns the runner of
// the management store set together with the function that closes the connection.
func NewMigrationRunner(ctx context.Context, kind types.Engine, dataDir string) (*migrate.Runner, func() error, error) {
	conn, err := OpenConn(ctx, kind, dataDir)
	if err != nil {
		return nil, nil, err
	}
	runner, err := migrate.New(conn.DB(nil), conn.Engine(), MigrationSet())
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return runner, conn.Close, nil
}

// storeModels lists every model the management store persists.
func storeModels() []any {
	return []any{
		&types.SetupKey{}, &nbpeer.Peer{}, &types.User{}, &types.PersonalAccessToken{}, &types.ProxyAccessToken{},
		&types.Group{}, &types.GroupPeer{},
		&types.Account{}, &types.Policy{}, &types.PolicyRule{}, &route.Route{}, &nbdns.NameServerGroup{},
		&installation{}, &types.ExtraSettings{}, &posture.Checks{}, &nbpeer.NetworkAddress{},
		&networkTypes.Network{}, &routerTypes.NetworkRouter{}, &resourceTypes.NetworkResource{}, &types.AccountOnboarding{},
		&types.Job{}, &zones.Zone{}, &records.Record{}, &types.UserInviteRecord{}, &rpservice.Service{}, &rpservice.Target{}, &domain.Domain{},
		&accesslogs.AccessLogEntry{}, &proxy.Proxy{},
		&agentNetworkTypes.Provider{}, &agentNetworkTypes.Policy{}, &agentNetworkTypes.Guardrail{}, &agentNetworkTypes.Settings{},
		&agentNetworkTypes.Consumption{}, &agentNetworkTypes.AccountBudgetRule{},
		&agentNetworkTypes.AgentNetworkAccessLog{}, &agentNetworkTypes.AgentNetworkAccessLogGroup{},
		&agentNetworkTypes.AgentNetworkUsage{}, &agentNetworkTypes.AgentNetworkUsageGroup{},
	}
}

// legacyMigrate is the schema path databases followed before versioned
// migrations: the hand-written migrations around gorm's AutoMigrate. It only
// runs for databases that predate the baseline.
func legacyMigrate(ctx context.Context, gormDB *gorm.DB) error {
	if err := migratePreAuto(ctx, gormDB); err != nil {
		return fmt.Errorf("migratePreAuto: %w", err)
	}
	if err := gormDB.AutoMigrate(storeModels()...); err != nil {
		return fmt.Errorf("auto migrate: %w", err)
	}
	if err := migratePostAuto(ctx, gormDB); err != nil {
		return fmt.Errorf("migratePostAuto: %w", err)
	}
	return nil
}
