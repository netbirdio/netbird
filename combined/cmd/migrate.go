package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter/hook"
	migratecmd "github.com/netbirdio/netbird/management/cmd/migrate"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
)

func newMigrateCommand() *cobra.Command {
	return migratecmd.NewCommand(withMigrationTargets)
}

// withMigrationTargets loads the combined YAML config, opens the management
// and activity stores plus every registered target for migration and calls fn.
func withMigrationTargets(cmd *cobra.Command, fn func(ctx context.Context, targets []migratecmd.Target) error) error {
	if err := util.InitLog("info", "console"); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := context.WithValue(cmd.Context(), hook.ExecutionContextKey, hook.SystemSource) //nolint:staticcheck

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.ApplyAdminDefaults()
	applyServerStoreEnv(cfg.Server.Store)
	if err := applyActivityStoreEnv(cfg.Server.ActivityStore); err != nil {
		return err
	}
	mgmtConfig, err := adminManagementConfig(cfg)
	if err != nil {
		return err
	}

	var targets []migratecmd.Target
	defer func() { _ = migratecmd.CloseAll(targets) }()

	storeTarget, err := migratecmd.StoreTarget(ctx, types.Engine(cfg.Management.Store.Engine), cfg.Management.DataDir)
	if err != nil {
		return err
	}
	targets = append(targets, storeTarget)

	activityTarget, err := migratecmd.ActivityTarget(ctx, mgmtConfig.Datadir, mgmtConfig.DataStoreEncryptionKey)
	if err != nil {
		return err
	}
	targets = append(targets, activityTarget)

	for _, open := range migrationTargets {
		opened, err := open(ctx, configPath, cfg)
		if err != nil {
			return err
		}
		targets = append(targets, opened...)
	}

	return fn(ctx, targets)
}

// TargetOpener opens a database the migrate command manages and returns one
// target per migration set of that database. It receives the path of the
// combined YAML config and its parsed form.
type TargetOpener func(ctx context.Context, configPath string, cfg *CombinedConfig) ([]migratecmd.Target, error)

var migrationTargets []TargetOpener

// AddMigrationTarget registers a database the migrate command manages in
// addition to the management and activity stores. An embedding binary calls
// it before Execute.
func AddMigrationTarget(open TargetOpener) {
	migrationTargets = append(migrationTargets, open)
}
