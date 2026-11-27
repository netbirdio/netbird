package networkmapdbfactory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	networkmap_sqlite "github.com/netbirdio/netbird/management/internals/network_map_db/sqlite"
	"github.com/netbirdio/netbird/management/internals/shared/requestbuffer"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/types"
	log "github.com/sirupsen/logrus"
)

const (
	// ReplicaDsnEnv names the Postgres DSN of a read replica serving network map data reads.
	ReplicaDsnEnv = "NB_STORE_ENGINE_POSTGRES_REPLICA_DSN"
	// replicaWaitEnv bounds how long a network map data read waits for the replica.
	replicaWaitEnv = "NB_NETWORK_MAP_DATA_REPLICA_WAIT"

	defaultReplicaWait = 2 * time.Second
)

var ErrNotSupportedStoreEngine = errors.New("unsupported store engine")

func NewNetworkMapDBStore(
	ctx context.Context,
	dbconfig *networkmapdb.NetworkMapDBStoreConfig,
	integratedPeerValidator integrated_validator.IntegratedValidator,
	extraSettingsManager settings.Manager,
	replicaPool *pgxpool.Pool,
	meter metric.Meter) (*networkmapdb.NetworkMapDBStoreImpl, error) {
	switch dbconfig.Kind {
	case types.SqliteStoreEngine:
		log.WithContext(ctx).Info("networkmap store is using SQLite")
		store, err := networkmap_sqlite.NewSqliteStore(dbconfig.SqliteDBFileName, dbconfig.SqliteDataDir)
		if err != nil {
			return nil, err
		}
		return &networkmapdb.NetworkMapDBStoreImpl{
			Store:                   store,
			IntegratedPeerValidator: integratedPeerValidator,
			ExtraSettingsManager:    extraSettingsManager,
		}, nil
	case types.PostgresStoreEngine:
		log.WithContext(ctx).Info("using Postgres store engine")
		store, err := networkmap_pgsql.NewPostgresqlStore(ctx, dbconfig.PostgresDSN)
		if err != nil {
			return nil, err
		}

		impl := &networkmapdb.NetworkMapDBStoreImpl{
			Store:                   store,
			IntegratedPeerValidator: integratedPeerValidator,
			ExtraSettingsManager:    extraSettingsManager,
		}

		pools := map[string]*pgxpool.Pool{"primary": store.Pool}
		if replicaPool != nil {
			impl.Replica = &networkmap_pgsql.PgStore{Pool: replicaPool}
			impl.ReplicaWait = requestbuffer.Interval(ctx, replicaWaitEnv, defaultReplicaWait)
			pools["replica"] = replicaPool
			replicaConfig := replicaPool.Config().ConnConfig
			log.WithContext(ctx).Infof("networkmap store reads from Postgres replica %s:%d/%s, waiting up to %s for replication",
				replicaConfig.Host, replicaConfig.Port, replicaConfig.Database, impl.ReplicaWait)
		} else {
			log.WithContext(ctx).Info("networkmap store reads from the primary, no replica configured")
		}

		if meter != nil {
			impl.Metrics, err = networkmapdb.NewMetrics(meter, pools)
			if err != nil {
				return nil, fmt.Errorf("create network map data metrics: %w", err)
			}
		}

		return impl, nil
	}

	return nil, fmt.Errorf("networkmap store doesn't support engine %s, %w", dbconfig.Kind, ErrNotSupportedStoreEngine)
}
