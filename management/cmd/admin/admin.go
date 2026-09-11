// Package admincmd provides reusable cobra commands for self-hosted administrator helpers.
// Both the management and combined binaries use these commands, each providing
// their own opener to handle config loading and storage initialization.
package admincmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/dexidp/dex/storage"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"github.com/netbirdio/netbird/formatter/hook"
	nbdex "github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/cmd/proxy"
	"github.com/netbirdio/netbird/management/cmd/token"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// Resources contains the storages required by the admin commands.
type Resources struct {
	Store          store.Store
	IDPStorage     storage.Storage
	IDPStorageFile string
	EventStore     activity.Store
}

// Opener initializes command resources from the command context and calls fn.
type Opener func(cmd *cobra.Command, fn func(ctx context.Context, resources Resources) error) error

// StoreOpener initializes only the management store from the command context and calls fn.
type StoreOpener func(cmd *cobra.Command, fn func(ctx context.Context, s store.Store) error) error

// IDPOpener initializes only the embedded IdP storage from the command context and calls fn.
type IDPOpener func(cmd *cobra.Command, fn func(ctx context.Context, idpStorage storage.Storage, storageFile string) error) error

// Openers contains the resource openers needed by the admin command tree.
type Openers struct {
	Resources Opener
	Store     StoreOpener
	IDP       IDPOpener
}

type userSelector struct {
	email  string
	userID string
}

func (s userSelector) normalized() userSelector {
	return userSelector{
		email:  strings.TrimSpace(s.email),
		userID: strings.TrimSpace(s.userID),
	}
}

func (s userSelector) validate() error {
	s = s.normalized()
	if (s.email == "") == (s.userID == "") {
		return fmt.Errorf("provide exactly one of --email or --user-id")
	}
	return nil
}

// NewCommands creates the admin command tree with the given resource openers.
func NewCommands(openers Openers) *cobra.Command {
	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Self-hosted administrator helpers",
		Long:  "Administrative helpers for self-hosted deployments using the embedded identity provider.",
	}

	userCmd := &cobra.Command{
		Use:   "user",
		Short: "Manage local embedded IdP users",
	}

	var passwordSelector userSelector
	var password string
	var passwordFile string
	passwordCmd := &cobra.Command{
		Use:     "change-password (--email email | --user-id id) (--password password | --password-file path)",
		Aliases: []string{"set-password"},
		Short:   "Change a local user's password",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := passwordSelector.validate(); err != nil {
				return err
			}
			newPassword, err := resolvePasswordInput(cmd, password, passwordFile)
			if err != nil {
				return err
			}
			return openers.IDP(cmd, func(ctx context.Context, idpStorage storage.Storage, storageFile string) error {
				return runChangePassword(ctx, idpStorage, cmd.OutOrStdout(), passwordSelector, newPassword, storageFile)
			})
		},
	}
	addUserSelectorFlags(passwordCmd, &passwordSelector)
	passwordCmd.Flags().StringVar(&password, "password", "", "New password for the user")
	passwordCmd.Flags().StringVar(&passwordFile, "password-file", "", "Read new password from file ('-' for stdin)")

	var resetSelector userSelector
	resetMFACmd := &cobra.Command{
		Use:   "reset-mfa (--email email | --user-id id)",
		Short: "Reset a local user's MFA enrollment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := resetSelector.validate(); err != nil {
				return err
			}
			return openers.IDP(cmd, func(ctx context.Context, idpStorage storage.Storage, storageFile string) error {
				return runResetMFA(ctx, idpStorage, cmd.OutOrStdout(), resetSelector, storageFile)
			})
		},
	}
	addUserSelectorFlags(resetMFACmd, &resetSelector)

	userCmd.AddCommand(passwordCmd, resetMFACmd)

	mfaCmd := &cobra.Command{
		Use:   "mfa",
		Short: "Manage local MFA for embedded IdP users",
	}

	enableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable MFA for local embedded IdP users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return openers.Resources(cmd, func(ctx context.Context, resources Resources) error {
				return runSetMFAEnabled(ctx, resources, cmd.OutOrStdout(), true)
			})
		},
	}

	disableCmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable MFA for local embedded IdP users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return openers.Resources(cmd, func(ctx context.Context, resources Resources) error {
				return runSetMFAEnabled(ctx, resources, cmd.OutOrStdout(), false)
			})
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show local MFA status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return openers.Resources(cmd, func(ctx context.Context, resources Resources) error {
				return runMFAStatus(ctx, resources, cmd.OutOrStdout())
			})
		},
	}

	mfaCmd.AddCommand(enableCmd, disableCmd, statusCmd)
	adminCmd.AddCommand(userCmd, mfaCmd)
	if openers.Store != nil {
		adminCmd.AddCommand(tokencmd.NewCommands(tokencmd.StoreOpener(openers.Store)))
		adminCmd.AddCommand(proxycmd.NewCommands(proxycmd.StoreOpener(openers.Store)))
	}
	return adminCmd
}

// OpenEmbeddedIDPStorage opens the Dex storage configured for the embedded IdP.
func OpenEmbeddedIDPStorage(cfg *idp.EmbeddedIdPConfig) (storage.Storage, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("admin commands require the embedded IdP to be enabled")
	}

	yamlConfig, err := cfg.ToYAMLConfig()
	if err != nil {
		return nil, fmt.Errorf("build embedded IdP config: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := yamlConfig.Storage.OpenStorage(logger)
	if err != nil {
		return nil, fmt.Errorf("open embedded IdP storage: %w", err)
	}
	return st, nil
}

// CloseStore closes the management store and logs cleanup errors at debug level.
func CloseStore(ctx context.Context, s store.Store) {
	if s == nil {
		return
	}
	if err := s.Close(ctx); err != nil {
		log.Debugf("close store: %v", err)
	}
}

// OpenIDPStorage opens embedded IdP storage and returns its sqlite file path when applicable.
func OpenIDPStorage(config *nbconfig.Config) (storage.Storage, string, error) {
	if config == nil {
		return nil, "", fmt.Errorf("management config is required")
	}
	idpStorage, err := OpenEmbeddedIDPStorage(config.EmbeddedIdP)
	if err != nil {
		return nil, "", err
	}
	return idpStorage, embeddedIDPStorageFile(config), nil
}

func embeddedIDPStorageFile(config *nbconfig.Config) string {
	if config.EmbeddedIdP == nil || config.EmbeddedIdP.Storage.Type != "sqlite3" {
		return ""
	}
	return config.EmbeddedIdP.Storage.Config.File
}

// CloseIDPStorage closes embedded IdP storage and logs cleanup errors at debug level.
func CloseIDPStorage(s storage.Storage) {
	if s == nil {
		return
	}
	if err := s.Close(); err != nil {
		log.Debugf("close embedded IdP storage: %v", err)
	}
}

func addUserSelectorFlags(cmd *cobra.Command, selector *userSelector) {
	cmd.Flags().StringVar(&selector.email, "email", "", "User email")
	cmd.Flags().StringVar(&selector.userID, "user-id", "", "User ID")
}

func resolvePasswordInput(cmd *cobra.Command, password, passwordFile string) (string, error) {
	if password != "" && passwordFile != "" {
		return "", fmt.Errorf("provide only one of --password or --password-file")
	}
	if passwordFile == "" {
		return password, nil
	}

	var data []byte
	var err error
	if passwordFile == "-" {
		data, err = io.ReadAll(cmd.InOrStdin())
	} else {
		data, err = os.ReadFile(passwordFile)
	}
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

func runChangePassword(ctx context.Context, idpStorage storage.Storage, w io.Writer, selector userSelector, password string, idpStorageFile string) error {
	if idpStorage == nil {
		return fmt.Errorf("embedded IdP storage is required")
	}
	selector = selector.normalized()
	if err := selector.validate(); err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}
	if err := server.ValidatePassword(password); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}

	user, err := findLocalUser(ctx, idpStorage, selector, idpStorageFile)
	if err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := idpStorage.UpdatePassword(ctx, user.Email, func(old storage.Password) (storage.Password, error) {
		old.Hash = hash
		return old, nil
	}); err != nil {
		return fmt.Errorf("update password for %s: %w", user.Email, err)
	}

	if err := deleteLocalAuthSession(ctx, idpStorage, user.UserID); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(w, "Password updated for %s.\n", user.Email)
	return nil
}

func runResetMFA(ctx context.Context, idpStorage storage.Storage, w io.Writer, selector userSelector, idpStorageFile string) error {
	if idpStorage == nil {
		return fmt.Errorf("embedded IdP storage is required")
	}
	selector = selector.normalized()
	if err := selector.validate(); err != nil {
		return err
	}

	user, err := findLocalUser(ctx, idpStorage, selector, idpStorageFile)
	if err != nil {
		return err
	}

	reset := false
	err = idpStorage.UpdateUserIdentity(ctx, user.UserID, idp.LocalConnectorID, func(old storage.UserIdentity) (storage.UserIdentity, error) {
		reset = reset || len(old.MFASecrets) > 0 || len(old.WebAuthnCredentials) > 0
		old.MFASecrets = map[string]*storage.MFASecret{}
		old.WebAuthnCredentials = map[string][]storage.WebAuthnCredential{}
		return old, nil
	})
	if errors.Is(err, storage.ErrNotFound) {
		if err := deleteLocalAuthSession(ctx, idpStorage, user.UserID); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "No MFA enrollment found for %s.\n", user.Email)
		return nil
	}
	if err != nil {
		return fmt.Errorf("reset MFA for %s: %w", user.Email, err)
	}

	if err := deleteLocalAuthSession(ctx, idpStorage, user.UserID); err != nil {
		return err
	}

	if reset {
		_, _ = fmt.Fprintf(w, "MFA reset for %s. The user will re-enroll at next login.\n", user.Email)
	} else {
		_, _ = fmt.Fprintf(w, "No MFA enrollment found for %s.\n", user.Email)
	}
	return nil
}

func runSetMFAEnabled(ctx context.Context, resources Resources, w io.Writer, enabled bool) error {
	if resources.Store == nil {
		return fmt.Errorf("management store is required")
	}
	if resources.IDPStorage == nil {
		return fmt.Errorf("embedded IdP storage is required")
	}

	accountID, settings, err := getSingleAccountSettings(ctx, resources.Store)
	if err != nil {
		return err
	}

	oldEnabled := settings.LocalMfaEnabled
	newSettings := settings.Copy()
	newSettings.LocalMfaEnabled = enabled

	if err := setIDPClientsMFA(ctx, resources.IDPStorage, enabled); err != nil {
		return err
	}

	if err := resources.Store.SaveAccountSettings(ctx, accountID, newSettings); err != nil {
		if rollbackErr := setIDPClientsMFA(ctx, resources.IDPStorage, oldEnabled); rollbackErr != nil {
			return fmt.Errorf("save local MFA account setting: %w (also failed to roll back embedded IdP MFA state: %v)", err, rollbackErr)
		}
		return fmt.Errorf("save local MFA account setting: %w", err)
	}

	if err := storeMFAActivity(ctx, resources.EventStore, accountID, enabled); err != nil {
		_, _ = fmt.Fprintf(w, "Warning: failed to record audit event: %v\n", err)
	}

	state := "disabled"
	if enabled {
		state = "enabled"
	}
	_, _ = fmt.Fprintf(w, "Local MFA %s.\n", state)
	return nil
}

func runMFAStatus(ctx context.Context, resources Resources, w io.Writer) error {
	if resources.Store == nil {
		return fmt.Errorf("management store is required")
	}
	if resources.IDPStorage == nil {
		return fmt.Errorf("embedded IdP storage is required")
	}

	_, settings, err := getSingleAccountSettings(ctx, resources.Store)
	if err != nil {
		return err
	}
	accountStatus := "disabled"
	if settings.LocalMfaEnabled {
		accountStatus = "enabled"
	}

	clientStatus, err := idpClientsMFAStatus(ctx, resources.IDPStorage)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(w, "Account setting: %s\n", accountStatus)
	_, _ = fmt.Fprintf(w, "Embedded IdP clients: %s\n", clientStatus)
	return nil
}

func getSingleAccountSettings(ctx context.Context, s store.Store) (string, *types.Settings, error) {
	count, err := s.GetAccountsCounter(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("count accounts: %w", err)
	}
	if count != 1 {
		return "", nil, fmt.Errorf("expected exactly one account, got %d; local MFA is supported only in single-account embedded IdP deployments", count)
	}

	accountID, err := s.GetAnyAccountID(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("get account ID: %w", err)
	}

	settings, err := s.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return "", nil, fmt.Errorf("get account settings: %w", err)
	}
	if settings == nil {
		settings = &types.Settings{}
	}
	return accountID, settings, nil
}

func storeMFAActivity(ctx context.Context, eventStore activity.Store, accountID string, enabled bool) error {
	if eventStore == nil {
		return nil
	}
	event := activity.AccountLocalMfaDisabled
	if enabled {
		event = activity.AccountLocalMfaEnabled
	}
	_, err := eventStore.Save(ctx, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    event,
		InitiatorID: string(hook.SystemSource),
		TargetID:    accountID,
		AccountID:   accountID,
	})
	if err != nil {
		return fmt.Errorf("save local MFA audit event: %w", err)
	}
	return nil
}

func findLocalUser(ctx context.Context, idpStorage storage.Storage, selector userSelector, idpStorageFile string) (storage.Password, error) {
	selector = selector.normalized()
	if err := selector.validate(); err != nil {
		return storage.Password{}, err
	}

	if selector.email != "" {
		user, err := idpStorage.GetPassword(ctx, selector.email)
		if errors.Is(err, storage.ErrNotFound) {
			if empty, listErr := localUsersEmpty(ctx, idpStorage); listErr != nil {
				return storage.Password{}, listErr
			} else if empty {
				return storage.Password{}, noLocalUsersError(idpStorageFile)
			}
			return storage.Password{}, fmt.Errorf("local user with email %q not found", selector.email)
		}
		if err != nil {
			return storage.Password{}, fmt.Errorf("get local user by email %q: %w", selector.email, err)
		}
		return user, nil
	}

	rawUserID := selector.userID
	if decodedUserID, _, err := nbdex.DecodeDexUserID(selector.userID); err == nil && decodedUserID != "" {
		rawUserID = decodedUserID
	}

	users, err := idpStorage.ListPasswords(ctx)
	if err != nil {
		return storage.Password{}, fmt.Errorf("list local users: %w", err)
	}
	for _, user := range users {
		if user.UserID == rawUserID || user.UserID == selector.userID {
			return user, nil
		}
	}

	if len(users) == 0 {
		return storage.Password{}, noLocalUsersError(idpStorageFile)
	}

	return storage.Password{}, fmt.Errorf("local user with ID %q not found", selector.userID)
}

func localUsersEmpty(ctx context.Context, idpStorage storage.Storage) (bool, error) {
	users, err := idpStorage.ListPasswords(ctx)
	if err != nil {
		return false, fmt.Errorf("list local users: %w", err)
	}
	return len(users) == 0, nil
}

func noLocalUsersError(idpStorageFile string) error {
	location := ""
	if idpStorageFile != "" {
		location = fmt.Sprintf(" (%s)", idpStorageFile)
	}
	return fmt.Errorf("no local users exist in the embedded IdP storage%s; the management server may never have started with this config, or --datadir points at the wrong location", location)
}

func deleteLocalAuthSession(ctx context.Context, idpStorage storage.Storage, userID string) error {
	err := idpStorage.DeleteAuthSession(ctx, userID, idp.LocalConnectorID)
	if err == nil || errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("delete local auth session for user %s: %w", userID, err)
}

func setIDPClientsMFA(ctx context.Context, idpStorage storage.Storage, enabled bool) error {
	var mfaChain []string
	if enabled {
		mfaChain = []string{idp.DefaultTOTPAuthenticatorID}
	}

	clientIDs := []string{idp.StaticClientCLI, idp.StaticClientDashboard}
	if err := nbdex.SetClientsMFAChain(ctx, idpStorage, clientIDs, mfaChain); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("embedded IdP client not found; start the management server once before toggling MFA: %w", err)
		}
		return fmt.Errorf("update MFA chain on embedded IdP clients: %w", err)
	}
	return nil
}

func idpClientsMFAStatus(ctx context.Context, idpStorage storage.Storage) (string, error) {
	clientIDs := []string{idp.StaticClientCLI, idp.StaticClientDashboard}
	enabledCount := 0
	for _, clientID := range clientIDs {
		client, err := idpStorage.GetClient(ctx, clientID)
		if errors.Is(err, storage.ErrNotFound) {
			return "unknown", fmt.Errorf("embedded IdP client %q not found", clientID)
		}
		if err != nil {
			return "unknown", fmt.Errorf("get embedded IdP client %q: %w", clientID, err)
		}
		if hasAuthenticator(client.MFAChain, idp.DefaultTOTPAuthenticatorID) {
			enabledCount++
		}
	}

	switch enabledCount {
	case 0:
		return "disabled", nil
	case len(clientIDs):
		return "enabled", nil
	default:
		return "partially enabled", nil
	}
}

func hasAuthenticator(chain []string, authenticatorID string) bool {
	for _, id := range chain {
		if id == authenticatorID {
			return true
		}
	}
	return false
}
