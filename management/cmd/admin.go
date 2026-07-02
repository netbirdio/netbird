package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter/hook"
	admincmd "github.com/netbirdio/netbird/management/cmd/admin"
	tokencmd "github.com/netbirdio/netbird/management/cmd/token"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/util"
)

var adminDatadir string

// newAdminCommands creates the admin command tree with management-specific resource openers.
func newAdminCommands() *cobra.Command {
	cmd := admincmd.NewCommands(withAdminResources)
	cmd.PersistentFlags().StringVar(&adminDatadir, "datadir", "", "Override the data directory from config (used for store.db and the default idp.db)")
	cmd.AddCommand(tokencmd.NewCommands(withAdminTokenStore))
	return cmd
}

// withAdminResources initializes logging, loads config, opens the management store
// and embedded IdP storage, and calls fn.
func withAdminResources(cmd *cobra.Command, fn func(ctx context.Context, resources admincmd.Resources) error) error {
	return withAdminStore(cmd, func(ctx context.Context, managementStore store.Store, config *nbconfig.Config) error {
		idpStorage, err := admincmd.OpenEmbeddedIDPStorage(config.EmbeddedIdP)
		if err != nil {
			return err
		}
		defer func() {
			if err := idpStorage.Close(); err != nil {
				log.Debugf("close embedded IdP storage: %v", err)
			}
		}()

		return fn(ctx, admincmd.Resources{Store: managementStore, IDPStorage: idpStorage})
	})
}

// withAdminTokenStore opens only the management store for admin token commands.
func withAdminTokenStore(cmd *cobra.Command, fn func(ctx context.Context, s store.Store) error) error {
	return withAdminStore(cmd, func(ctx context.Context, managementStore store.Store, _ *nbconfig.Config) error {
		return fn(ctx, managementStore)
	})
}

func withAdminStore(cmd *cobra.Command, fn func(ctx context.Context, s store.Store, config *nbconfig.Config) error) error {
	if err := util.InitLog("error", "console"); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := context.WithValue(cmd.Context(), hook.ExecutionContextKey, hook.SystemSource) //nolint:staticcheck

	config, err := LoadMgmtConfig(ctx, nbconfig.MgmtConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	datadir := config.Datadir
	if adminDatadir != "" {
		oldDatadir := datadir
		datadir = adminDatadir
		if config.EmbeddedIdP != nil && config.EmbeddedIdP.Storage.Type == "sqlite3" {
			defaultIDPFile := filepath.Join(oldDatadir, "idp.db")
			if config.EmbeddedIdP.Storage.Config.File == "" || config.EmbeddedIdP.Storage.Config.File == defaultIDPFile {
				config.EmbeddedIdP.Storage.Config.File = filepath.Join(datadir, "idp.db")
			}
		}
	}

	managementStore, err := store.NewStore(ctx, config.StoreConfig.Engine, datadir, nil, true)
	if err != nil {
		return fmt.Errorf("create store: %w", err)
	}
	defer func() {
		if err := managementStore.Close(ctx); err != nil {
			log.Debugf("close store: %v", err)
		}
	}()

	return fn(ctx, managementStore, config)
}
