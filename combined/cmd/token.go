package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter/hook"
	tokencmd "github.com/netbirdio/netbird/management/cmd/token"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
)

// newTokenCommands creates the token command tree with combined-specific store opener.
func newTokenCommands() *cobra.Command {
	return tokencmd.NewCommands(withTokenStore)
}

// withTokenStore loads the combined YAML config, initializes the store, and calls fn.
func withTokenStore(cmd *cobra.Command, fn func(ctx context.Context, s store.Store) error) error {
	if err := util.InitLog("error", "console"); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := context.WithValue(cmd.Context(), hook.ExecutionContextKey, hook.SystemSource) //nolint:staticcheck

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if dsn := cfg.Server.Store.DSN; dsn != "" {
		switch strings.ToLower(cfg.Server.Store.Engine) {
		case "postgres":
			os.Setenv("NB_STORE_ENGINE_POSTGRES_DSN", dsn)
		case "mysql":
			os.Setenv("NB_STORE_ENGINE_MYSQL_DSN", dsn)
		}
	}

	datadir := cfg.Management.DataDir
	engine := types.Engine(cfg.Management.Store.Engine)

	s, err := store.NewStore(ctx, engine, datadir, nil, true)
	if err != nil {
		return fmt.Errorf("create store: %w", err)
	}
	defer func() {
		if err := s.Close(ctx); err != nil {
			log.Debugf("close store: %v", err)
		}
	}()

	return fn(ctx, s)
}
