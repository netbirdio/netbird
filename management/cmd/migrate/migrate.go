// Package migratecmd provides the `migrate` command tree shared by the
// management and the combined binary.
package migratecmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"

	accesslogsmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs/manager"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// Target is one database with its migration set, opened for the duration of a command.
type Target struct {
	Name   string
	Runner *migrate.Runner
	Close  func() error
}

// Opener loads the configuration, opens every target and hands them to fn.
type Opener func(cmd *cobra.Command, fn func(ctx context.Context, targets []Target) error) error

// NewCommand builds the migrate command tree on top of open.
func NewCommand(open Opener) *cobra.Command {
	var names []string
	var upTo, planTo int64
	selected := func(cmd *cobra.Command, fn func(ctx context.Context, targets []Target) error) error {
		return open(cmd, func(ctx context.Context, targets []Target) error {
			targets, err := selectTargets(targets, names)
			if err != nil {
				return err
			}
			return fn(ctx, targets)
		})
	}

	migrateCmd := &cobra.Command{
		Use:          "migrate",
		Short:        "Manage the database schema versions of the server",
		SilenceUsage: true,
	}
	migrateCmd.PersistentFlags().StringSliceVar(&names, "target", nil, "limit the command to these databases (store, accesslogs, activity, ...); all when empty. Every configured database is still opened")

	upCmd := &cobra.Command{
		Use:   "up",
		Short: "Apply pending schema migrations and exit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return selected(cmd, func(ctx context.Context, targets []Target) error {
				return up(ctx, cmd.OutOrStdout(), targets, upTo)
			})
		},
	}
	upCmd.Flags().Int64Var(&upTo, "to", 0, "apply pending migrations up to and including this version only; all when 0")

	planCmd := &cobra.Command{
		Use:   "plan",
		Short: "Print the pending migrations and their SQL without applying them",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return selected(cmd, func(ctx context.Context, targets []Target) error {
				return plan(ctx, cmd.OutOrStdout(), targets, planTo)
			})
		},
	}
	planCmd.Flags().Int64Var(&planTo, "to", 0, "show pending migrations up to and including this version only; all when 0")

	migrateCmd.AddCommand(
		upCmd,
		&cobra.Command{
			Use:   "status",
			Short: "Print every migration with its applied state",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return selected(cmd, func(ctx context.Context, targets []Target) error {
					return status(ctx, cmd.OutOrStdout(), targets)
				})
			},
		},
		planCmd,
	)
	return migrateCmd
}

// StoreTarget opens the management store of the given engine and data
// directory as a migrate target.
func StoreTarget(ctx context.Context, engine types.Engine, datadir string) (Target, error) {
	runner, closeConn, err := store.NewMigrationRunner(ctx, engine, datadir)
	if err != nil {
		return Target{}, fmt.Errorf("open store: %w", err)
	}
	return Target{Name: "store", Runner: runner, Close: closeConn}, nil
}

// ActivityTarget opens the activity event store as a migrate target; its
// legacy bootstrap needs the data store encryption key.
func ActivityTarget(ctx context.Context, datadir, encryptionKey string) (Target, error) {
	if encryptionKey == "" {
		return Target{}, fmt.Errorf("open activity store: data store encryption key is not configured")
	}
	runner, closeConn, err := activitystore.NewMigrationRunner(ctx, datadir, encryptionKey)
	if err != nil {
		return Target{}, fmt.Errorf("open activity store: %w", err)
	}
	return Target{Name: "activity", Runner: runner, Close: closeConn}, nil
}

// AccessLogTarget opens the reverse proxy access log store, which follows the
// main store's engine unless configured otherwise, as a migrate target.
func AccessLogTarget(ctx context.Context, datadir string, mainEngine db.Engine) (Target, error) {
	runner, closeConn, err := accesslogsmanager.NewMigrationRunner(ctx, datadir, mainEngine)
	if err != nil {
		return Target{}, fmt.Errorf("open access log store: %w", err)
	}
	return Target{Name: "accesslogs", Runner: runner, Close: closeConn}, nil
}

// CloseAll releases every target, keeping the first close error.
func CloseAll(targets []Target) error {
	var firstErr error
	for _, target := range targets {
		if err := target.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close %s: %w", target.Name, err)
		}
	}
	return firstErr
}

func up(ctx context.Context, out io.Writer, targets []Target, to int64) error {
	suffix := ""
	if to == 0 {
		to = goose.MaxVersion
	} else {
		if err := checkVersion(targets, to); err != nil {
			return err
		}
		suffix = fmt.Sprintf(" up to %d", to)
	}
	for _, target := range targets {
		if err := target.Runner.UpTo(ctx, to); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: schema is current%s\n", target.Name, suffix)
	}
	return nil
}

func status(ctx context.Context, out io.Writer, targets []Target) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DATABASE\tVERSION\tSTATE\tAPPLIED AT\tSOURCE")
	for _, target := range targets {
		statuses, err := target.Runner.Status(ctx)
		if err != nil {
			return err
		}
		for _, s := range statuses {
			appliedAt := ""
			if s.State == goose.StateApplied {
				appliedAt = s.AppliedAt.UTC().Format("2006-01-02 15:04:05")
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", target.Name, s.Source.Version, s.State, appliedAt, sourceName(s.Source))
		}
	}
	return w.Flush()
}

func plan(ctx context.Context, out io.Writer, targets []Target, to int64) error {
	if to == 0 {
		to = goose.MaxVersion
	} else if err := checkVersion(targets, to); err != nil {
		return err
	}
	for _, target := range targets {
		pending, err := target.Runner.PendingUpTo(ctx, to)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			fmt.Fprintf(out, "-- %s: nothing pending\n", target.Name)
			continue
		}
		for _, migration := range pending {
			fmt.Fprintf(out, "-- %s: %d %s\n", target.Name, migration.Version, migration.Path)
			if migration.Type == goose.TypeGo {
				fmt.Fprintln(out, "-- Go migration, no SQL to show")
				continue
			}
			fmt.Fprintln(out, strings.TrimRight(migration.SQL, "\n"))
		}
	}
	return nil
}

// selectTargets keeps the targets named in names, in their opening order, and
// every target when names is empty.
func selectTargets(targets []Target, names []string) ([]Target, error) {
	if len(names) == 0 {
		return targets, nil
	}

	available := make([]string, 0, len(targets))
	byName := make(map[string]Target, len(targets))
	for _, target := range targets {
		available = append(available, target.Name)
		byName[target.Name] = target
	}

	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		if _, ok := byName[name]; !ok {
			return nil, fmt.Errorf("unknown target %q, available: %s", name, strings.Join(available, ", "))
		}
		wanted[name] = true
	}

	var selected []Target
	for _, target := range targets {
		if wanted[target.Name] {
			selected = append(selected, target)
		}
	}
	return selected, nil
}

// checkVersion rejects a target version that is no migration of any selected
// database, so a mistyped version does not silently act as a cutoff.
func checkVersion(targets []Target, version int64) error {
	for _, target := range targets {
		if target.Runner.HasVersion(version) {
			return nil
		}
	}
	return fmt.Errorf("version %d is not a migration of the selected databases, see `migrate status`", version)
}

func sourceName(source *goose.Source) string {
	if source.Path == "" {
		return "go"
	}
	return source.Path
}
