package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter/hook"
	admincmd "github.com/netbirdio/netbird/management/cmd/admin"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
)

// newAdminCommands creates the admin command tree with combined-specific resource opener.
func newAdminCommands() *cobra.Command {
	return admincmd.NewCommands(withAdminResources)
}

// withAdminResources loads the combined YAML config, initializes stores, and calls fn.
func withAdminResources(cmd *cobra.Command, fn func(ctx context.Context, resources admincmd.Resources) error) error {
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
	if file := cfg.Server.Store.File; file != "" {
		os.Setenv("NB_STORE_ENGINE_SQLITE_FILE", file)
	}

	managementStore, err := store.NewStore(ctx, types.Engine(cfg.Management.Store.Engine), cfg.Management.DataDir, nil, true)
	if err != nil {
		return fmt.Errorf("create store: %w", err)
	}
	defer func() {
		if err := managementStore.Close(ctx); err != nil {
			log.Debugf("close store: %v", err)
		}
	}()

	mgmtConfig, err := cfg.ToManagementConfig()
	if err != nil {
		return fmt.Errorf("create management config: %w", err)
	}
	idpStorage, err := admincmd.OpenEmbeddedIDPStorage(mgmtConfig.EmbeddedIdP)
	if err != nil {
		return err
	}
	defer func() {
		if err := idpStorage.Close(); err != nil {
			log.Debugf("close embedded IdP storage: %v", err)
		}
	}()

	return fn(ctx, admincmd.Resources{Store: managementStore, IDPStorage: idpStorage})
}
