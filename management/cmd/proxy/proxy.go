// Package proxycmd provides reusable cobra commands for managing reverse proxy instances.
// Both the management and combined binaries use these commands, each providing
// their own StoreOpener to handle config loading and store initialization.
package proxycmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/store"
)

// StoreOpener initializes a store from the command context and calls fn.
type StoreOpener func(cmd *cobra.Command, fn func(ctx context.Context, s store.Store) error) error

const disconnectAllConfirmation = "disconnect all proxies"

// NewCommands creates the proxy command tree with the given store opener.
// Returns the parent "proxy" command with the disconnect-all subcommand.
func NewCommands(opener StoreOpener) *cobra.Command {
	var dryRun bool
	var force bool

	proxyCmd := &cobra.Command{
		Use:   "proxy",
		Short: "Manage reverse proxy instances",
		Long:  "Commands for inspecting and repairing the reverse proxy instances registered with the management server.",
	}

	disconnectAllCmd := &cobra.Command{
		Use:   "disconnect-all",
		Short: "Force-mark all reverse proxy instances as disconnected",
		Long: "Lists all reverse proxy instances and force-marks them as disconnected, regardless of their session state. " +
			"Use this to repair stale connection state, e.g. after an unclean management server shutdown. " +
			"By default, it asks for manual confirmation before changing state. Use --dry-run to preview without changing state, or --force to skip confirmation. " +
			"Run during a maintenance window; affected live proxies may stay hidden until their next heartbeat or reconnect/re-register.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return opener(cmd, func(ctx context.Context, s store.Store) error {
				return runDisconnectAll(ctx, s, cmd.OutOrStdout(), cmd.InOrStdin(), dryRun, force)
			})
		},
	}
	disconnectAllCmd.Flags().BoolVar(&dryRun, "dry-run", false, "List reverse proxy instances that would be disconnected without changing state")
	disconnectAllCmd.Flags().BoolVar(&force, "force", false, "Skip the confirmation prompt and apply the repair")

	proxyCmd.AddCommand(disconnectAllCmd)
	return proxyCmd
}

func runDisconnectAll(ctx context.Context, s store.Store, out io.Writer, in io.Reader, dryRun, force bool) error {
	proxies, err := s.GetAllProxies(ctx)
	if err != nil {
		return fmt.Errorf("list proxies: %w", err)
	}

	if len(proxies) == 0 {
		_, _ = fmt.Fprintln(out, "No reverse proxy instances found.")
		return nil
	}

	toDisconnect := 0
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tCLUSTER\tIP\tACCOUNT\tSTATUS\tLAST SEEN")
	_, _ = fmt.Fprintln(w, "--\t-------\t--\t-------\t------\t---------")

	for _, p := range proxies {
		if p.Status != rpproxy.StatusDisconnected {
			toDisconnect++
		}

		account := "-"
		if p.AccountID != nil {
			account = *p.AccountID
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			p.ID,
			p.ClusterAddress,
			p.IPAddress,
			account,
			p.Status,
			p.LastSeen.Format("2006-01-02 15:04:05"),
		)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("write proxy list: %w", err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(out, "\nDry run: would force-mark %d of %d reverse proxy instance(s) as disconnected.\n", toDisconnect, len(proxies))
		return nil
	}

	if !force {
		confirmed, err := confirmDisconnectAll(out, in)
		if err != nil {
			return err
		}
		if !confirmed {
			_, _ = fmt.Fprintln(out, "Aborted. No reverse proxy instances were changed.")
			return nil
		}
	}

	disconnected, err := s.DisconnectAllProxies(ctx)
	if err != nil {
		return fmt.Errorf("disconnect proxies: %w", err)
	}

	_, _ = fmt.Fprintf(out, "\nForce-marked %d of %d reverse proxy instance(s) as disconnected.\n", disconnected, len(proxies))
	return nil
}

func confirmDisconnectAll(out io.Writer, in io.Reader) (bool, error) {
	if in == nil {
		in = strings.NewReader("")
	}

	_, _ = fmt.Fprintln(out, "\nWARNING: This command changes stored reverse proxy state for every non-disconnected instance.")
	_, _ = fmt.Fprintln(out, "Run it during a maintenance window; affected live proxies may stay hidden until "+
		"their next heartbeat or reconnect/re-register.")
	_, _ = fmt.Fprintf(out, "Type %q to continue: ", disconnectAllConfirmation)

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, fmt.Errorf("read confirmation: %w", err)
		}
		return false, nil
	}

	return strings.EqualFold(strings.TrimSpace(scanner.Text()), disconnectAllConfirmation), nil
}
