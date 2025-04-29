//go:build !ios
// +build !ios

package testutil

import (
	"context"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

// CreateMysqlTestContainer creates a new MySQL container for testing.
func CreateMysqlTestContainer() (func(), error) {
	ctx := context.Background()

	myContainer, err := mysql.RunContainer(ctx,
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
		return nil, err
	}

	cleanup := func() {
		os.Unsetenv("NETBIRD_STORE_ENGINE_MYSQL_DSN")
		timeoutCtx, cancelFunc := context.WithTimeout(ctx, 1*time.Second)
		defer cancelFunc()
		if err = myContainer.Terminate(timeoutCtx); err != nil {
			log.WithContext(ctx).Warnf("failed to stop mysql container %s: %s", myContainer.GetContainerID(), err)
		}
	}

	talksConn, err := myContainer.ConnectionString(ctx)
	if err != nil {
		return nil, err
	}

	return cleanup, os.Setenv("NETBIRD_STORE_ENGINE_MYSQL_DSN", talksConn)
}

// CreatePostgresTestContainer creates a new PostgreSQL container for testing.
func CreatePostgresTestContainer() (func(), error) {
	ctx := context.Background()

	pgContainer, err := postgres.RunContainer(ctx,
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
		return nil, err
	}

	cleanup := func() {
		os.Unsetenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN")
		timeoutCtx, cancelFunc := context.WithTimeout(ctx, 1*time.Second)
		defer cancelFunc()
		if err = pgContainer.Terminate(timeoutCtx); err != nil {
			log.WithContext(ctx).Warnf("failed to stop postgres container %s: %s", pgContainer.GetContainerID(), err)
		}
	}

	talksConn, err := pgContainer.ConnectionString(ctx)
	if err != nil {
		return nil, err
	}

	return cleanup, os.Setenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN", talksConn)
}

// CreateRedisTestContainer creates a new Redis container for testing.
func CreateRedisTestContainer() (func(), string, error) {
	ctx := context.Background()

	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
	if err != nil {
		return nil, "", err
	}

	cleanup := func() {
		timeoutCtx, cancelFunc := context.WithTimeout(ctx, 1*time.Second)
		defer cancelFunc()
		if err = redisContainer.Terminate(timeoutCtx); err != nil {
			log.WithContext(ctx).Warnf("failed to stop redis container %s: %s", redisContainer.GetContainerID(), err)
		}
	}

	redisURL, err := redisContainer.ConnectionString(ctx)
	if err != nil {
		return nil, "", err
	}

	return cleanup, redisURL, nil
}
