package networkmapdbfactory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	networkmap_sqlite "github.com/netbirdio/netbird/management/internals/network_map_db/sqlite"
	"github.com/netbirdio/netbird/management/internals/shared/requestbuffer"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	log "github.com/sirupsen/logrus"
)

const (
	storeSqliteFileName = "store.db"

	// ReplicaDsnEnv names the Postgres DSN of a read replica serving network map data reads.
	ReplicaDsnEnv = "NB_STORE_ENGINE_POSTGRES_REPLICA_DSN"
	// replicaWaitEnv bounds how long a network map data read waits for the replica.
	replicaWaitEnv = "NB_NETWORK_MAP_DATA_REPLICA_WAIT"

	defaultReplicaWait = 2 * time.Second
)

var ErrNotSupportedStoreEngine = errors.New("unsupported store engine")

func NewNetworkMapDBStore(
	ctx context.Context,
	kind types.Engine,
	dataDir string,
	integratedPeerValidator integrated_validator.IntegratedValidator,
	extraSettingsManager settings.Manager,
	replicaPool *pgxpool.Pool) (*networkmapdb.NetworkMapDBStoreImpl, error) {
	switch kind {
	case types.SqliteStoreEngine:
		log.WithContext(ctx).Info("networkmap store is using SQLite")
		storeFile := storeSqliteFileName
		if envFile, ok := os.LookupEnv("NB_STORE_ENGINE_SQLITE_FILE"); ok && envFile != "" {
			storeFile = envFile
		}
		store, err := networkmap_sqlite.NewSqliteStore(storeFile, dataDir)
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
		dsn, err := mustLookupDsnEnv()
		if err != nil {
			return nil, err
		}

		store, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
		if err != nil {
			return nil, err
		}

		impl := &networkmapdb.NetworkMapDBStoreImpl{
			Store:                   store,
			IntegratedPeerValidator: integratedPeerValidator,
			ExtraSettingsManager:    extraSettingsManager,
		}

		if replicaPool != nil {
			impl.Replica = &networkmap_pgsql.PgStore{Pool: replicaPool}
			impl.ReplicaWait = requestbuffer.Interval(ctx, replicaWaitEnv, defaultReplicaWait)
			log.WithContext(ctx).Infof("networkmap store reads from Postgres replica, waiting up to %s for replication", impl.ReplicaWait)
		}

		return impl, nil
	}

	return nil, fmt.Errorf("networkmap store doesn't support engine %s, %w", kind, ErrNotSupportedStoreEngine)
}

func mustLookupDsnEnv() (string, error) {
	if v, ok := os.LookupEnv(store.PostgresDsnEnv); ok {
		return v, nil
	}
	if v, ok := os.LookupEnv(store.PostgresDsnEnvLegacy); ok {
		return v, nil
	}

	return "", fmt.Errorf("%s env var must be set when using postgres networkmap store", store.PostgresDsnEnv)
}
