// Package tokencmd provides reusable cobra commands for managing proxy access tokens.
// Both the management and combined binaries use these commands, each providing
// their own StoreOpener to handle config loading and store initialization.
package tokencmd

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// StoreOpener initializes a store from the command context and calls fn.
type StoreOpener func(cmd *cobra.Command, fn func(ctx context.Context, s store.Store) error) error

// NewCommands creates the token command tree with the given store opener.
// Returns the parent "token" command with create, list, and revoke subcommands.
func NewCommands(opener StoreOpener) *cobra.Command {
	var (
		tokenName     string
		tokenExpireIn string
	)

	tokenCmd := &cobra.Command{
		Use:   "token",
		Short: "Manage proxy access tokens",
		Long:  "Commands for creating, listing, and revoking proxy access tokens used by reverse proxy instances to authenticate with the management server.",
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new proxy access token",
		Long:  "Creates a new proxy access token. The plain text token is displayed only once at creation time.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return opener(cmd, func(ctx context.Context, s store.Store) error {
				return runCreate(ctx, s, cmd.OutOrStdout(), tokenName, tokenExpireIn)
			})
		},
	}
	createCmd.Flags().StringVar(&tokenName, "name", "", "Name for the token (required)")
	createCmd.Flags().StringVar(&tokenExpireIn, "expires-in", "", "Token expiration duration (e.g., 365d, 24h, 30d). Empty means no expiration")
	if err := createCmd.MarkFlagRequired("name"); err != nil {
		panic(err)
	}

	listCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all proxy access tokens",
		Long:    "Lists all proxy access tokens with their IDs, names, creation dates, expiration, and revocation status.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return opener(cmd, func(ctx context.Context, s store.Store) error {
				return runList(ctx, s, cmd.OutOrStdout())
			})
		},
	}

	revokeCmd := &cobra.Command{
		Use:   "revoke [token-id]",
		Short: "Revoke a proxy access token",
		Long:  "Revokes a proxy access token by its ID. Revoked tokens can no longer be used for authentication.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return opener(cmd, func(ctx context.Context, s store.Store) error {
				return runRevoke(ctx, s, cmd.OutOrStdout(), args[0])
			})
		},
	}

	tokenCmd.AddCommand(createCmd, listCmd, revokeCmd)
	return tokenCmd
}

func runCreate(ctx context.Context, s store.Store, w io.Writer, name string, expireIn string) error {
	expiresIn, err := ParseDuration(expireIn)
	if err != nil {
		return fmt.Errorf("parse expiration: %w", err)
	}

	generated, err := types.CreateNewProxyAccessToken(name, expiresIn, nil, "CLI")
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	if err := s.SaveProxyAccessToken(ctx, &generated.ProxyAccessToken); err != nil {
		return fmt.Errorf("save token: %w", err)
	}

	_, _ = fmt.Fprintln(w, "Token created successfully!")
	_, _ = fmt.Fprintf(w, "Token: %s\n", generated.PlainToken)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "IMPORTANT: Save this token now. It will not be shown again.")
	_, _ = fmt.Fprintf(w, "Token ID: %s\n", generated.ID)
	return nil
}

func runList(ctx context.Context, s store.Store, out io.Writer) error {
	tokens, err := s.GetAllProxyAccessTokens(ctx, store.LockingStrengthNone)
	if err != nil {
		return fmt.Errorf("list tokens: %w", err)
	}

	if len(tokens) == 0 {
		_, _ = fmt.Fprintln(out, "No proxy access tokens found.")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tNAME\tCREATED\tEXPIRES\tLAST USED\tREVOKED")
	_, _ = fmt.Fprintln(w, "--\t----\t-------\t-------\t---------\t-------")

	for _, t := range tokens {
		expires := "never"
		if t.ExpiresAt != nil {
			expires = t.ExpiresAt.Format("2006-01-02")
		}

		lastUsed := "never"
		if t.LastUsed != nil {
			lastUsed = t.LastUsed.Format("2006-01-02 15:04")
		}

		revoked := "no"
		if t.Revoked {
			revoked = "yes"
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			t.ID,
			t.Name,
			t.CreatedAt.Format("2006-01-02"),
			expires,
			lastUsed,
			revoked,
		)
	}

	w.Flush()

	return nil
}

func runRevoke(ctx context.Context, s store.Store, w io.Writer, tokenID string) error {
	if err := s.RevokeProxyAccessToken(ctx, tokenID); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}

	_, _ = fmt.Fprintf(w, "Token %s revoked successfully.\n", tokenID)
	return nil
}

// ParseDuration parses a duration string with support for days (e.g., "30d", "365d").
// An empty string returns zero duration (no expiration).
func ParseDuration(s string) (time.Duration, error) {
	if len(s) == 0 {
		return 0, nil
	}

	if s[len(s)-1] == 'd' {
		d, err := strconv.Atoi(s[:len(s)-1])
		if err != nil {
			return 0, fmt.Errorf("invalid day format: %s", s)
		}
		if d <= 0 {
			return 0, fmt.Errorf("duration must be positive: %s", s)
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive: %s", s)
	}
	return d, nil
}
