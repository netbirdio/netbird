//go:build !ios
// +build !ios

package testutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	mysqlContainerConfigPath = "../testdata/mysql.cnf"
	mysqlContainer           = (*mysql.MySQLContainer)(nil)
	postgresContainer        = (*postgres.PostgresContainer)(nil)
	mysqlConnStr             = ""
	postgresConnStr          = ""
)

func emptyCleanup() { return }

// CreateMysqlTestContainer creates a new MySQL container for testing.
func CreateMysqlTestContainer() (func(), error) {
	ctx := context.Background()

	if mysqlContainer != nil && mysqlContainer.IsRunning() {
		refreshMysqlDatabase(ctx)
		return emptyCleanup, os.Setenv("NETBIRD_STORE_ENGINE_MYSQL_DSN", mysqlConnStr)
	}

	_, caller, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("failed to get caller information")
	}

	container, err := mysql.RunContainer(ctx,
		testcontainers.WithImage("mysql:8.0.40"),
		mysql.WithConfigFile(filepath.Join(filepath.Dir(caller), mysqlContainerConfigPath)),
		mysql.WithDatabase("netbird"),
		mysql.WithUsername("root"),
		mysql.WithPassword("netbird"),
	)
	if err != nil {
		return nil, err
	}

	talksConn, err := container.ConnectionString(ctx)
	if err != nil {
		return nil, err
	}
	mysqlContainer = container
	mysqlConnStr = talksConn

	return emptyCleanup, os.Setenv("NETBIRD_STORE_ENGINE_MYSQL_DSN", talksConn)
}

// CreatePostgresTestContainer creates a new PostgreSQL container for testing.
func CreatePostgresTestContainer() (func(), error) {
	ctx := context.Background()

	if postgresContainer != nil && postgresContainer.IsRunning() {
		refreshPostgresDatabase(ctx)
		return emptyCleanup, os.Setenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN", postgresConnStr)
	}

	container, err := postgres.RunContainer(ctx,
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

	talksConn, err := container.ConnectionString(ctx)
	if err != nil {
		return nil, err
	}
	postgresContainer = container
	postgresConnStr = talksConn

	return emptyCleanup, os.Setenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN", talksConn)
}

func refreshMysqlDatabase(ctx context.Context) {
	_, _, _ = mysqlContainer.Exec(ctx, []string{"mysqladmin", "--user=root", "drop", "netbird", "-f"})
	_, _, _ = mysqlContainer.Exec(ctx, []string{"mysqladmin", "--user=root", "create", "netbird"})
}

func refreshPostgresDatabase(ctx context.Context) {
	_, _, _ = postgresContainer.Exec(ctx, []string{"dropdb", "-f", "netbird"})
	_, _, _ = postgresContainer.Exec(ctx, []string{"createdb", "netbird"})
}
