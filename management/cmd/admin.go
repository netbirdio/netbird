package cmd

import (
	"context"
	"fmt"
	"path"
	"path/filepath"

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
	"github.com/netbirdio/netbird/util"
)

var adminDatadir string

// newAdminCommands creates the admin command tree with management-specific resource openers.
func newAdminCommands() *cobra.Command {
	cmd := admincmd.NewCommands(admincmd.Openers{
		Resources: withAdminResources,
		Store:     withAdminStoreOnly,
		IDP:       withAdminIDPOnly,
	})
	cmd.PersistentFlags().StringVar(&adminDatadir, "datadir", "", "Override the data directory from config (used for store.db and the default idp.db)")
	return cmd
}

func newLegacyTokenCommand() *cobra.Command {
	cmd := tokencmd.NewCommands(tokencmd.StoreOpener(withAdminStoreOnly))
	cmd.Deprecated = "use 'admin token' instead"
	cmd.PersistentFlags().StringVar(&nbconfig.MgmtConfigPath, "config", defaultMgmtConfig, "Netbird config file location")
	return cmd
}

// withAdminResources initializes logging, loads config, opens the management store
// and embedded IdP storage, and calls fn.
func withAdminResources(cmd *cobra.Command, fn func(ctx context.Context, resources admincmd.Resources) error) error {
	return withAdminConfig(cmd, true, func(ctx context.Context, config *nbconfig.Config, datadir string) error {
		managementStore, err := openAdminStore(ctx, config, datadir)
		if err != nil {
			return err
		}
		defer admincmd.CloseStore(ctx, managementStore)

		idpStorage, idpStorageFile, err := admincmd.OpenIDPStorage(config)
		if err != nil {
			return err
		}
		defer admincmd.CloseIDPStorage(idpStorage)

		eventStore, esErr := openAdminEventStore(ctx, config, datadir)
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
	return withAdminConfig(cmd, false, func(ctx context.Context, config *nbconfig.Config, datadir string) error {
		managementStore, err := openAdminStore(ctx, config, datadir)
		if err != nil {
			return err
		}
		defer admincmd.CloseStore(ctx, managementStore)

		return fn(ctx, managementStore)
	})
}

func withAdminIDPOnly(cmd *cobra.Command, fn func(ctx context.Context, idpStorage storage.Storage, storageFile string) error) error {
	return withAdminConfig(cmd, true, func(ctx context.Context, config *nbconfig.Config, _ string) error {
		idpStorage, idpStorageFile, err := admincmd.OpenIDPStorage(config)
		if err != nil {
			return err
		}
		defer admincmd.CloseIDPStorage(idpStorage)

		return fn(ctx, idpStorage, idpStorageFile)
	})
}

func withAdminConfig(cmd *cobra.Command, applyIDPDefaults bool, fn func(ctx context.Context, config *nbconfig.Config, datadir string) error) error {
	if err := util.InitLog("error", "console"); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := context.WithValue(cmd.Context(), hook.ExecutionContextKey, hook.SystemSource) //nolint:staticcheck

	config, datadir, err := loadAdminMgmtConfig(ctx, applyIDPDefaults)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	return fn(ctx, config, datadir)
}

func loadAdminMgmtConfig(ctx context.Context, applyIDPDefaults bool) (*nbconfig.Config, string, error) {
	config := &nbconfig.Config{}
	if _, err := util.ReadJsonWithEnvSub(nbconfig.MgmtConfigPath, config); err != nil {
		return nil, "", err
	}

	if applyIDPDefaults {
		if err := ApplyEmbeddedIdPConfig(ctx, config); err != nil {
			return nil, "", err
		}
	}

	datadir := config.Datadir
	applyAdminDatadirOverride(config, &datadir)
	return config, datadir, nil
}

func applyAdminDatadirOverride(config *nbconfig.Config, datadir *string) {
	if adminDatadir == "" {
		return
	}

	oldDatadir := *datadir
	*datadir = adminDatadir
	if config.EmbeddedIdP != nil && config.EmbeddedIdP.Storage.Type == "sqlite3" && isDefaultIDPStorageFile(config.EmbeddedIdP.Storage.Config.File, oldDatadir) {
		config.EmbeddedIdP.Storage.Config.File = filepath.Join(*datadir, "idp.db")
	}
}

func isDefaultIDPStorageFile(file, datadir string) bool {
	if file == "" {
		return true
	}
	defaultFile := filepath.Join(datadir, "idp.db")
	legacyDefaultFile := path.Join(datadir, "idp.db")
	legacySlashDefaultFile := path.Join(filepath.ToSlash(datadir), "idp.db")
	return filepath.Clean(file) == filepath.Clean(defaultFile) ||
		file == legacyDefaultFile ||
		filepath.ToSlash(file) == legacySlashDefaultFile
}

func openAdminStore(ctx context.Context, config *nbconfig.Config, datadir string) (store.Store, error) {
	managementStore, err := store.NewStore(ctx, config.StoreConfig.Engine, datadir, nil, true)
	if err != nil {
		return nil, fmt.Errorf("create store: %w", err)
	}
	return managementStore, nil
}

func openAdminEventStore(ctx context.Context, config *nbconfig.Config, datadir string) (activity.Store, error) {
	if config.DataStoreEncryptionKey == "" {
		return nil, fmt.Errorf("data store encryption key is not configured")
	}
	eventStore, err := activitystore.NewSqlStore(ctx, datadir, config.DataStoreEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("open activity event store: %w", err)
	}
	if eventStore == nil {
		return nil, fmt.Errorf("open activity event store: returned nil store")
	}
	return eventStore, nil
}
