package networkmap_pgsql

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

const (
	pgMaxConnections    = 30
	pgMinConnections    = 1
	pgMaxConnLifetime   = 60 * time.Minute
	pgHealthCheckPeriod = 1 * time.Minute
)

var _ networkmapdb.NetworkMapDBStore = &PgStore{}

type PgStore struct {
	Pool *pgxpool.Pool
}

type PgStoreConn struct {
	Conn pgInterface
}

type pgInterface interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

var _ networkmapdb.NetworkMapDBStoreConn = &PgStoreConn{}

func NewPostgresqlStore(ctx context.Context, dsn string) (*PgStore, error) {
	pool, err := connectToPgDb(ctx, dsn)
	if err != nil {
		return nil, err
	}

	return &PgStore{Pool: pool}, nil
}

func (p *PgStore) UsingConnection(c *pgx.Conn) networkmapdb.NetworkMapDBStoreConn {
	return &PgStoreConn{Conn: c}
}

func (p *PgStore) BeginTx(ctx context.Context) (networkmapdb.NetworkMapDBStoreConn, error) {
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	return &PgStoreConn{Conn: tx}, nil
}

func (c *PgStoreConn) RollbackTx(ctx context.Context) error {
	tx, ok := c.Conn.(pgx.Tx)
	if !ok {
		return fmt.Errorf("expected an pgx.Tx got %s", reflect.TypeOf(c.Conn).Kind())
	}
	return tx.Rollback(ctx)
}

func (c *PgStoreConn) CommitTx(ctx context.Context) error {
	tx, ok := c.Conn.(pgx.Tx)
	if !ok {
		return fmt.Errorf("expected an sql.Tx got %s", reflect.TypeOf(c.Conn).Kind())
	}
	return tx.Commit(ctx)
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
