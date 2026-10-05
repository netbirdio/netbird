package cmd

import (
	"context"
	"fmt"

	"github.com/dexidp/dex/storage"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter/hook"
	admincmd "github.com/netbirdio/netbird/management/cmd/admin"
	tokencmd "github.com/netbirdio/netbird/management/cmd/token"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/activity"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
)

// newAdminCommands creates the admin command tree with combined-specific resource openers.
func newAdminCommands() *cobra.Command {
	return admincmd.NewCommands(admincmd.Openers{
		Resources: withAdminResources,
		Store:     withAdminStoreOnly,
		IDP:       withAdminIDPOnly,
	})
}

func newLegacyTokenCommand() *cobra.Command {
	cmd := tokencmd.NewCommands(tokencmd.StoreOpener(withAdminStoreOnly))
	cmd.Deprecated = "use 'admin token' instead"
	return cmd
}

// withAdminResources loads the combined YAML config, initializes stores, and calls fn.
func withAdminResources(cmd *cobra.Command, fn func(ctx context.Context, resources admincmd.Resources) error) error {
	return withAdminConfig(cmd, func(ctx context.Context, cfg *CombinedConfig) error {
		mgmtConfig, err := adminManagementConfig(cfg)
		if err != nil {
			return err
		}

		managementStore, err := openAdminStore(ctx, cfg)
		if err != nil {
			return err
		}
		defer admincmd.CloseStore(ctx, managementStore)

		idpStorage, idpStorageFile, err := admincmd.OpenIDPStorage(mgmtConfig)
		if err != nil {
			return err
		}
		defer admincmd.CloseIDPStorage(idpStorage)

		eventStore, esErr := openAdminEventStore(ctx, cfg, mgmtConfig)
		if esErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: audit events will not be recorded: %v\n", esErr)
		}
		if eventStore != nil {
			defer func() {
				if err := eventStore.Close(ctx); err != nil {
					log.Debugf("close activity event store: %v", err)
				}
			}()
		}

		return fn(ctx, admincmd.Resources{Store: managementStore, IDPStorage: idpStorage, IDPStorageFile: idpStorageFile, EventStore: eventStore})
	})
}

// withAdminStoreOnly opens only the management store for admin subcommands that do not
// need embedded IdP storage.
func withAdminStoreOnly(cmd *cobra.Command, fn func(ctx context.Context, s store.Store) error) error {
	return withAdminConfig(cmd, func(ctx context.Context, cfg *CombinedConfig) error {
		managementStore, err := openAdminStore(ctx, cfg)
		if err != nil {
			return err
		}
		defer admincmd.CloseStore(ctx, managementStore)

		return fn(ctx, managementStore)
	})
}

func withAdminIDPOnly(cmd *cobra.Command, fn func(ctx context.Context, idpStorage storage.Storage, storageFile string) error) error {
	return withAdminConfig(cmd, func(ctx context.Context, cfg *CombinedConfig) error {
		mgmtConfig, err := adminManagementConfig(cfg)
		if err != nil {
			return err
		}
		idpStorage, idpStorageFile, err := admincmd.OpenIDPStorage(mgmtConfig)
		if err != nil {
			return err
		}
		defer admincmd.CloseIDPStorage(idpStorage)

		return fn(ctx, idpStorage, idpStorageFile)
	})
}

func withAdminConfig(cmd *cobra.Command, fn func(ctx context.Context, cfg *CombinedConfig) error) error {
	if err := util.InitLog("error", "console"); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := context.WithValue(cmd.Context(), hook.ExecutionContextKey, hook.SystemSource) //nolint:staticcheck

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.ApplyAdminDefaults()
	applyServerStoreEnv(cfg.Server.Store)

	return fn(ctx, cfg)
}

func adminManagementConfig(cfg *CombinedConfig) (*nbconfig.Config, error) {
	mgmtConfig, err := cfg.ToManagementConfig()
	if err != nil {
		return nil, fmt.Errorf("create management config: %w", err)
	}
	return mgmtConfig, nil
}

func openAdminStore(ctx context.Context, cfg *CombinedConfig) (store.Store, error) {
	managementStore, err := store.NewStore(ctx, types.Engine(cfg.Management.Store.Engine), cfg.Management.DataDir, nil, true)
	if err != nil {
		return nil, fmt.Errorf("create store: %w", err)
	}
	return managementStore, nil
}

func openAdminEventStore(ctx context.Context, cfg *CombinedConfig, config *nbconfig.Config) (activity.Store, error) {
	if config.DataStoreEncryptionKey == "" {
		return nil, fmt.Errorf("data store encryption key is not configured")
	}
	if err := applyActivityStoreEnv(cfg.Server.ActivityStore); err != nil {
		return nil, fmt.Errorf("configure activity event store: %w", err)
	}
	eventStore, err := activitystore.NewSqlStore(ctx, config.Datadir, config.DataStoreEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("open activity event store: %w", err)
	}
	if eventStore == nil {
		return nil, fmt.Errorf("open activity event store: returned nil store")
	}
	return eventStore, nil
}
