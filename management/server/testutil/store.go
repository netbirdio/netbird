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

	log "github.com/sirupsen/logrus"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var mysqlContainerConfigPath = "../testdata/mysql.cnf"

func CreateMysqlTestContainer() (func(), error) {
	ctx := context.Background()

	_, caller, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("failed to get caller information")
	}

	container, err := mysql.Run(ctx,
		"mysql:8.0.40",
		mysql.WithConfigFile(filepath.Join(filepath.Dir(caller), mysqlContainerConfigPath)),
		mysql.WithDatabase("netbird"),
		mysql.WithUsername("root"),
		mysql.WithPassword("netbird"),
	)
	if err != nil {
		return nil, err
	}

	cleanup := func() {
		timeout := 10 * time.Second
		if err = container.Stop(ctx, &timeout); err != nil {
			log.WithContext(ctx).Warnf("failed to stop container: %s", err)
		}
	}

	talksConn, err := container.ConnectionString(ctx)
	if err != nil {
		return cleanup, err
	}

	return cleanup, os.Setenv("NETBIRD_STORE_ENGINE_MYSQL_DSN", talksConn)
}

func CreatePostgresTestContainer() (func(), error) {
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
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
		timeout := 10 * time.Second
		if err = container.Stop(ctx, &timeout); err != nil {
			log.WithContext(ctx).Warnf("failed to stop container: %s", err)
		}
	}

	talksConn, err := container.ConnectionString(ctx)
	if err != nil {
		return cleanup, err
	}

	return cleanup, os.Setenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN", talksConn)
}
