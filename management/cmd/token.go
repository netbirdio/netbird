package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter/hook"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
)

var (
	tokenName     string
	tokenExpireIn string
	tokenDatadir  string

	tokenCmd = &cobra.Command{
		Use:   "token",
		Short: "Manage proxy access tokens",
		Long:  "Commands for creating, listing, and revoking proxy access tokens used by reverse proxy instances to authenticate with the management server.",
	}

	tokenCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a new proxy access token",
		Long:  "Creates a new proxy access token. The plain text token is displayed only once at creation time.",
		RunE:  tokenCreateRun,
	}

	tokenListCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all proxy access tokens",
		Long:    "Lists all proxy access tokens with their IDs, names, creation dates, expiration, and revocation status.",
		RunE:    tokenListRun,
	}

	tokenRevokeCmd = &cobra.Command{
		Use:   "revoke [token-id]",
		Short: "Revoke a proxy access token",
		Long:  "Revokes a proxy access token by its ID. Revoked tokens can no longer be used for authentication.",
		Args:  cobra.ExactArgs(1),
		RunE:  tokenRevokeRun,
	}
)

func init() {
	tokenCmd.PersistentFlags().StringVar(&tokenDatadir, "datadir", "", "Override the data directory from config (where store.db is located)")

	tokenCreateCmd.Flags().StringVar(&tokenName, "name", "", "Name for the token (required)")
	tokenCreateCmd.Flags().StringVar(&tokenExpireIn, "expires-in", "", "Token expiration duration (e.g., 365d, 24h, 30d). Empty means no expiration")
	tokenCreateCmd.MarkFlagRequired("name") //nolint
}

// withTokenStore initializes logging, loads config, opens the store, and calls fn.
func withTokenStore(cmd *cobra.Command, fn func(ctx context.Context, s store.Store) error) error {
	if err := util.InitLog("error", "console"); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := context.WithValue(cmd.Context(), hook.ExecutionContextKey, hook.SystemSource)

	config, err := loadMgmtConfig(ctx, nbconfig.MgmtConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	datadir := config.Datadir
	if tokenDatadir != "" {
		datadir = tokenDatadir
	}

	s, err := store.NewStore(ctx, config.StoreConfig.Engine, datadir, nil, true)
	if err != nil {
		return fmt.Errorf("create store: %w", err)
	}
	defer func() {
		if err := s.Close(ctx); err != nil {
			log.Debugf("close store: %v", err)
		}
	}()

	return fn(ctx, s)
}

func tokenCreateRun(cmd *cobra.Command, _ []string) error {
	return withTokenStore(cmd, func(ctx context.Context, s store.Store) error {
		expiresIn, err := parseDuration(tokenExpireIn)
		if err != nil {
			return fmt.Errorf("parse expiration: %w", err)
		}

		generated, err := types.CreateNewProxyAccessToken(tokenName, expiresIn, nil, "CLI")
		if err != nil {
			return fmt.Errorf("generate token: %w", err)
		}

		if err := s.SaveProxyAccessToken(ctx, &generated.ProxyAccessToken); err != nil {
			return fmt.Errorf("save token: %w", err)
		}

		fmt.Println("Token created successfully!")
		fmt.Printf("Token: %s\n", generated.PlainToken)
		fmt.Println()
		fmt.Println("IMPORTANT: Save this token now. It will not be shown again.")
		fmt.Printf("Token ID: %s\n", generated.ID)

		return nil
	})
}

func tokenListRun(cmd *cobra.Command, _ []string) error {
	return withTokenStore(cmd, func(ctx context.Context, s store.Store) error {
		tokens, err := s.GetAllProxyAccessTokens(ctx, store.LockingStrengthNone)
		if err != nil {
			return fmt.Errorf("list tokens: %w", err)
		}

		if len(tokens) == 0 {
			fmt.Println("No proxy access tokens found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tCREATED\tEXPIRES\tLAST USED\tREVOKED")
		fmt.Fprintln(w, "--\t----\t-------\t-------\t---------\t-------")

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

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
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
	})
}

func tokenRevokeRun(cmd *cobra.Command, args []string) error {
	return withTokenStore(cmd, func(ctx context.Context, s store.Store) error {
		tokenID := args[0]

		if err := s.RevokeProxyAccessToken(ctx, tokenID); err != nil {
			return fmt.Errorf("revoke token: %w", err)
		}

		fmt.Printf("Token %s revoked successfully.\n", tokenID)
		return nil
	})
}

// parseDuration parses a duration string with support for days (e.g., "30d", "365d").
// An empty string returns zero duration (no expiration).
func parseDuration(s string) (time.Duration, error) {
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
