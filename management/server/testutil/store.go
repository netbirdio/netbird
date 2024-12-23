//go:build !ios
// +build !ios

package testutil

import (
	"context"
	"os"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	mysqlContainer           = (*mysql.MySQLContainer)(nil)
	mysqlContainerString     = ""
	mysqlContainerConfigPath = "../../management/server/testdata/mysql.cnf"
	postgresContainer        = (*postgres.PostgresContainer)(nil)
	postgresContainerString  = ""
)

func emptyCleanup() {
	// Empty function, don't do anything.
}

func CreateMysqlTestContainer() (func(), error) {

	ctx := context.Background()

	if mysqlContainerString != "" && mysqlContainer != nil && mysqlContainer.IsRunning() {
		RefreshMysqlDatabase(ctx)
		return emptyCleanup, os.Setenv("NETBIRD_STORE_ENGINE_MYSQL_DSN", mysqlContainerString)
	}

	container, err := mysql.Run(ctx,
		"mysql:8.0.40",
		mysql.WithConfigFile(mysqlContainerConfigPath),
		mysql.WithDatabase("netbird"),
		mysql.WithUsername("root"),
		mysql.WithPassword(""),
	)

	if err != nil {
		return nil, err
	}

	talksConn, _ := container.ConnectionString(ctx)

	mysqlContainer = container
	mysqlContainerString = talksConn

	RefreshMysqlDatabase(ctx)
	return emptyCleanup, os.Setenv("NETBIRD_STORE_ENGINE_MYSQL_DSN", talksConn)
}

func CreatePostgresTestContainer() (func(), error) {

	ctx := context.Background()

	if postgresContainerString != "" && postgresContainer != nil && postgresContainer.IsRunning() {
		RefreshPostgresDatabase(ctx)
		return emptyCleanup, os.Setenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN", postgresContainerString)
	}

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("netbird"),
		postgres.WithUsername("root"),
		postgres.WithPassword("netbird"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(15*time.Second)),
	)
	if err != nil {
		return nil, err
	}

	talksConn, _ := container.ConnectionString(ctx)

	postgresContainerString = talksConn
	postgresContainer = container

	RefreshPostgresDatabase(ctx)
	return emptyCleanup, os.Setenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN", postgresContainerString)
}

func RefreshMysqlDatabase(ctx context.Context) {
	_, _, _ = mysqlContainer.Exec(ctx, []string{"mysqladmin", "--user=root", "drop", "netbird", "-f"})
	_, _, _ = mysqlContainer.Exec(ctx, []string{"mysqladmin", "--user=root", "create", "netbird"})
}

func RefreshPostgresDatabase(ctx context.Context) {
	_, _, _ = postgresContainer.Exec(ctx, []string{"dropdb", "-f", "netbird"})
	_, _, _ = postgresContainer.Exec(ctx, []string{"createdb", "netbird"})
}
