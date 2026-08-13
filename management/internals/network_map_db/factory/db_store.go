package networkmapdbfactory

import (
	"context"
	"errors"
	"fmt"
	"os"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	networkmap_sqlite "github.com/netbirdio/netbird/management/internals/network_map_db/sqlite"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	log "github.com/sirupsen/logrus"
)

const storeSqliteFileName = "store.db"

var ErrNotSupportedStoreEngine = errors.New("unsupported store engine")

func NewNetworkMapDBStore(
	ctx context.Context,
	kind types.Engine,
	dataDir string,
	integratedPeerValidator integrated_validator.IntegratedValidator,
	extraSettingsManager settings.Manager) (*networkmapdb.NetworkMapDBStoreImpl, error) {
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

		return &networkmapdb.NetworkMapDBStoreImpl{
			Store:                   store,
			IntegratedPeerValidator: integratedPeerValidator,
			ExtraSettingsManager:    extraSettingsManager,
		}, nil
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
