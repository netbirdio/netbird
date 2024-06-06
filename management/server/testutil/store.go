//go:build !ios
// +build !ios

package testutil

import (
	"context"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func CreatePGDB() (func(), error) {
	ctx := context.Background()
	c, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:alpine"),
		postgres.WithDatabase("test"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(15*time.Second)),
	)
	if err != nil {
		return nil, err
	}

	cleanup := func() {
		timeout := 10 * time.Second
		err = c.Stop(ctx, &timeout)
		if err != nil {
			log.Warnf("failed to stop container: %s", err)
		}
	}

	talksConn, err := c.ConnectionString(ctx)
	if err != nil {
		return cleanup, err
	}
	return cleanup, os.Setenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN", talksConn)
}
