package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter/hook"
	migratecmd "github.com/netbirdio/netbird/management/cmd/migrate"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/util"
)

// TargetOpener opens a database the migrate command manages and returns one
// target per migration set of that database.
type TargetOpener func(ctx context.Context, config *nbconfig.Config, datadir string) ([]migratecmd.Target, error)

var migrationTargets = []TargetOpener{openStoreTarget, openActivityTarget}

// AddMigrationTarget registers a database the migrate command manages in
// addition to the management and activity stores. An embedding binary calls
// it before Execute.
func AddMigrationTarget(open TargetOpener) {
	migrationTargets = append(migrationTargets, open)
}

func newMigrateCommand() *cobra.Command {
	migrateCmd := migratecmd.NewCommand(withMigrationTargets)
	migrateCmd.PersistentFlags().StringVar(&nbconfig.MgmtConfigPath, "config", defaultMgmtConfig, "Netbird config file location")
	migrateCmd.PersistentFlags().StringVar(&adminDatadir, "datadir", "", "server data directory location, overrides the config file")
	return migrateCmd
}

func withMigrationTargets(cmd *cobra.Command, fn func(ctx context.Context, targets []migratecmd.Target) error) error {
	if err := util.InitLog(logLevel, "console"); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := context.WithValue(cmd.Context(), hook.ExecutionContextKey, hook.SystemSource) //nolint:staticcheck

	config, datadir, err := loadAdminMgmtConfig(ctx, false)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	targets, err := openMigrationTargets(ctx, config, datadir)
	if err != nil {
		return err
	}
	defer migratecmd.CloseAll(targets) //nolint:errcheck

	return fn(ctx, targets)
}

func openMigrationTargets(ctx context.Context, config *nbconfig.Config, datadir string) ([]migratecmd.Target, error) {
	var targets []migratecmd.Target
	for _, open := range migrationTargets {
		opened, err := open(ctx, config, datadir)
		if err != nil {
			_ = migratecmd.CloseAll(targets)
			return nil, err
		}
		targets = append(targets, opened...)
	}
	return targets, nil
}

func openStoreTarget(ctx context.Context, config *nbconfig.Config, datadir string) ([]migratecmd.Target, error) {
	target, err := migratecmd.StoreTarget(ctx, config.StoreConfig.Engine, datadir)
	if err != nil {
		return nil, err
	}
	return []migratecmd.Target{target}, nil
}

func openActivityTarget(ctx context.Context, config *nbconfig.Config, datadir string) ([]migratecmd.Target, error) {
	target, err := migratecmd.ActivityTarget(ctx, datadir, config.DataStoreEncryptionKey)
	if err != nil {
		return nil, err
	}
	return []migratecmd.Target{target}, nil
}
