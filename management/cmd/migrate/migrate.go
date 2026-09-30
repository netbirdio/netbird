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
	migrateCmd := &cobra.Command{
		Use:          "migrate",
		Short:        "Manage the database schema versions of the server",
		SilenceUsage: true,
	}
	migrateCmd.AddCommand(
		&cobra.Command{
			Use:   "up",
			Short: "Apply pending schema migrations and exit",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return open(cmd, func(ctx context.Context, targets []Target) error {
					return up(ctx, cmd.OutOrStdout(), targets)
				})
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Print every migration with its applied state",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return open(cmd, func(ctx context.Context, targets []Target) error {
					return status(ctx, cmd.OutOrStdout(), targets)
				})
			},
		},
		&cobra.Command{
			Use:   "plan",
			Short: "Print the pending migrations and their SQL without applying them",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return open(cmd, func(ctx context.Context, targets []Target) error {
					return plan(ctx, cmd.OutOrStdout(), targets)
				})
			},
		},
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

func up(ctx context.Context, out io.Writer, targets []Target) error {
	for _, target := range targets {
		if err := target.Runner.Run(ctx, migrate.ModeAuto); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: schema is current\n", target.Name)
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

func plan(ctx context.Context, out io.Writer, targets []Target) error {
	for _, target := range targets {
		pending, err := target.Runner.Pending(ctx)
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

func sourceName(source *goose.Source) string {
	if source.Path == "" {
		return "go"
	}
	return source.Path
}
