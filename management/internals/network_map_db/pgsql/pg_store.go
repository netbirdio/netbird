package networkmap_pgsql

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/settings"
)

const (
	pgMaxConnections    = 30
	pgMinConnections    = 1
	pgMaxConnLifetime   = 60 * time.Minute
	pgHealthCheckPeriod = 1 * time.Minute
)

var _ networkmapdb.NetworkMapDBStore = &PgStore{}

type PgStore struct {
	Pool                    *pgxpool.Pool
	integratedPeerValidator integrated_validator.IntegratedValidator
	settingsManager         settings.Manager
}

func NewPostgresqlStore(ctx context.Context, dsn string) (*PgStore, error) {
	pool, err := connectToPgDb(context.Background(), dsn)
	if err != nil {
		return nil, err
	}

	return &PgStore{Pool: pool}, nil
}

func connectToPgDb(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	config.MaxConns = pgMaxConnections
	config.MinConns = pgMinConnections
	config.MaxConnLifetime = pgMaxConnLifetime
	config.HealthCheckPeriod = pgHealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return pool, nil
}
