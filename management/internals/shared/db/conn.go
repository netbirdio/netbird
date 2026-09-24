package db

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const (
	defaultTransactionTimeout = 5 * time.Minute
	connMaxLifetime           = time.Hour
	connMaxIdleTime           = 3 * time.Minute
)

// TxMetrics receives the duration of every committed top-level transaction.
type TxMetrics interface {
	CountTransactionDuration(duration time.Duration)
}

// Conn is the database connection shared by all repositories: one gorm handle,
// the pgx pool of a Postgres deployment and the engine they talk to.
type Conn struct {
	db        *gorm.DB
	pool      *pgxpool.Pool
	engine    Engine
	txTimeout time.Duration
	metrics   TxMetrics
}

// NewConn takes ownership of an open gorm handle and pool, applying the
// connection limits and transaction timeout configured through the environment.
func NewConn(ctx context.Context, gormDB *gorm.DB, engine Engine, pool *pgxpool.Pool) (*Conn, error) {
	sqlDB, err := gormDB.DB()
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, err
	}

	conns, err := strconv.Atoi(os.Getenv("NB_SQL_MAX_OPEN_CONNS"))
	if err != nil {
		conns = runtime.NumCPU()
	}

	txTimeout := defaultTransactionTimeout
	if v := os.Getenv("NB_STORE_TRANSACTION_TIMEOUT"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			txTimeout = parsed
		}
	}
	log.WithContext(ctx).Infof("Setting transaction timeout to %v", txTimeout)

	if engine == SqliteStoreEngine {
		if err == nil {
			log.WithContext(ctx).Warnf("setting NB_SQL_MAX_OPEN_CONNS is not supported for sqlite, using default value 1")
		}
		conns = 1
	}

	sqlDB.SetMaxOpenConns(conns)
	sqlDB.SetMaxIdleConns(conns)
	sqlDB.SetConnMaxLifetime(connMaxLifetime)
	sqlDB.SetConnMaxIdleTime(connMaxIdleTime)

	log.WithContext(ctx).Infof("Set max open db connections to %d, max idle to %d, max lifetime to %v, max idle time to %v",
		conns, conns, connMaxLifetime, connMaxIdleTime)

	return &Conn{db: gormDB, pool: pool, engine: engine, txTimeout: txTimeout}, nil
}

// DB returns the handle a query must run on: the transaction when tx is set,
// otherwise the shared connection.
func (c *Conn) DB(tx *Tx) *gorm.DB {
	if tx != nil {
		return tx.db
	}
	return c.db
}

// Pool returns the pgx pool for read paths that bypass gorm. It is nil on
// engines other than Postgres and inside a transaction, where the pool would
// not see the uncommitted writes.
func (c *Conn) Pool(tx *Tx) *pgxpool.Pool {
	if tx != nil {
		return nil
	}
	return c.pool
}

func (c *Conn) Engine() Engine {
	return c.engine
}

// SetTxMetrics registers the sink that receives transaction durations.
func (c *Conn) SetTxMetrics(metrics TxMetrics) {
	c.metrics = metrics
}

// AutoMigrate creates or updates the tables of the given models.
func (c *Conn) AutoMigrate(models ...any) error {
	return c.db.AutoMigrate(models...)
}

// Close releases the gorm connection and the pgx pool.
func (c *Conn) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	sqlDB, err := c.db.DB()
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	return sqlDB.Close()
}
