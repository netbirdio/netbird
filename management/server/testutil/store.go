//go:build !ios
// +build !ios

package testutil

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	pgContainer    *postgres.PostgresContainer
	mysqlContainer *mysql.MySQLContainer
)

// CreateMysqlTestContainer creates a new MySQL container for testing.
func CreateMysqlTestContainer() (func(), string, error) {
	ctx := context.Background()

	if mysqlContainer != nil {
		connStr, err := mysqlContainer.ConnectionString(ctx)
		if err != nil {
			return nil, "", err
		}
		return noOpCleanup, connStr, nil
	}

	var err error
	mysqlContainer, err = mysql.RunContainer(ctx,
		testcontainers.WithImage("mlsmaycon/warmed-mysql:8"),
		mysql.WithDatabase("testing"),
		mysql.WithUsername("root"),
		mysql.WithPassword("testing"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("/usr/sbin/mysqld: ready for connections").
				WithOccurrence(1).WithStartupTimeout(15*time.Second).WithPollInterval(100*time.Millisecond),
		),
	)
	if err != nil {
		return nil, "", err
	}

	cleanup := func() {
		timeoutCtx, cancelFunc := context.WithTimeout(ctx, 1*time.Second)
		defer cancelFunc()
		if err = mysqlContainer.Terminate(timeoutCtx); err != nil {
			log.WithContext(ctx).Warnf("failed to stop mysql container %s: %s", mysqlContainer.GetContainerID(), err)
		}
	}

	talksConn, err := mysqlContainer.ConnectionString(ctx)
	if err != nil {
		return nil, "", err
	}

	return cleanup, talksConn, nil
}

// CreatePostgresTestContainer creates a new PostgreSQL container for testing.
func CreatePostgresTestContainer() (func(), string, error) {
	ctx := context.Background()

	if pgContainer != nil {
		connStr, err := pgContainer.ConnectionString(ctx)
		if err != nil {
			return nil, "", err
		}
		return noOpCleanup, connStr, nil
	}

	var err error
	pgContainer, err = postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		postgres.WithDatabase("netbird"),
		postgres.WithUsername("root"),
		postgres.WithPassword("netbird"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(15*time.Second),
		),
	)
	if err != nil {
		return nil, "", err
	}

	cleanup := func() {
		timeoutCtx, cancelFunc := context.WithTimeout(ctx, 1*time.Second)
		defer cancelFunc()
		if err = pgContainer.Terminate(timeoutCtx); err != nil {
			log.WithContext(ctx).Warnf("failed to stop postgres container %s: %s", pgContainer.GetContainerID(), err)
		}
	}

	talksConn, err := pgContainer.ConnectionString(ctx)
	if err != nil {
		return nil, "", err
	}

	return cleanup, talksConn, nil
}

func noOpCleanup() {
	// no-op
}
