package admincmd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	nbdex "github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	mgmtstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func newTestIDPStorage(t *testing.T) storage.Storage {
	t.Helper()

	st := memory.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	hash, err := bcrypt.GenerateFromPassword([]byte("OldPass1!"), bcrypt.DefaultCost)
	require.NoError(t, err)

	require.NoError(t, st.CreatePassword(context.Background(), storage.Password{
		Email:    "user@example.com",
		Username: "User",
		UserID:   "user-1",
		Hash:     hash,
	}))
	require.NoError(t, st.CreateUserIdentity(context.Background(), storage.UserIdentity{
		UserID:      "user-1",
		ConnectorID: idp.LocalConnectorID,
		MFASecrets: map[string]*storage.MFASecret{
			idp.DefaultTOTPAuthenticatorID: {
				AuthenticatorID: idp.DefaultTOTPAuthenticatorID,
				Type:            "TOTP",
				Secret:          "otpauth://totp/NetBird:user@example.com?secret=ABC",
				Confirmed:       true,
				CreatedAt:       time.Now(),
			},
		},
		WebAuthnCredentials: map[string][]storage.WebAuthnCredential{
			"webauthn": {{CredentialID: []byte("credential")}},
		},
	}))
	require.NoError(t, st.CreateAuthSession(context.Background(), storage.AuthSession{
		UserID:      "user-1",
		ConnectorID: idp.LocalConnectorID,
		Nonce:       "nonce",
	}))
	require.NoError(t, st.CreateClient(context.Background(), storage.Client{ID: idp.StaticClientCLI, Name: "CLI"}))
	require.NoError(t, st.CreateClient(context.Background(), storage.Client{ID: idp.StaticClientDashboard, Name: "Dashboard"}))

	return st
}

func TestRunChangePassword(t *testing.T) {
	ctx := context.Background()
	st := newTestIDPStorage(t)
	var out bytes.Buffer

	err := runChangePassword(ctx, st, &out, userSelector{email: "user@example.com"}, "NewPass1!", "")
	require.NoError(t, err)
	require.Contains(t, out.String(), "Password updated")

	user, err := st.GetPassword(ctx, "user@example.com")
	require.NoError(t, err)
	require.NoError(t, bcrypt.CompareHashAndPassword(user.Hash, []byte("NewPass1!")))

	_, err = st.GetAuthSession(ctx, "user-1", idp.LocalConnectorID)
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestRunChangePasswordValidatesPassword(t *testing.T) {
	st := newTestIDPStorage(t)
	err := runChangePassword(context.Background(), st, io.Discard, userSelector{email: "user@example.com"}, "short", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid password")
}

func TestRunResetMFA(t *testing.T) {
	ctx := context.Background()
	st := newTestIDPStorage(t)
	var out bytes.Buffer

	encodedUserID := nbdex.EncodeDexUserID("user-1", idp.LocalConnectorID)
	err := runResetMFA(ctx, st, &out, userSelector{userID: encodedUserID}, "")
	require.NoError(t, err)
	require.Contains(t, out.String(), "MFA reset")

	identity, err := st.GetUserIdentity(ctx, "user-1", idp.LocalConnectorID)
	require.NoError(t, err)
	require.Empty(t, identity.MFASecrets)
	require.Empty(t, identity.WebAuthnCredentials)

	_, err = st.GetAuthSession(ctx, "user-1", idp.LocalConnectorID)
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestRunResetMFAWithoutEnrollment(t *testing.T) {
	ctx := context.Background()
	st := newTestIDPStorage(t)
	require.NoError(t, st.UpdateUserIdentity(ctx, "user-1", idp.LocalConnectorID, func(old storage.UserIdentity) (storage.UserIdentity, error) {
		old.MFASecrets = nil
		old.WebAuthnCredentials = nil
		return old, nil
	}))

	var out bytes.Buffer
	err := runResetMFA(ctx, st, &out, userSelector{email: "user@example.com"}, "")
	require.NoError(t, err)
	require.Contains(t, out.String(), "No MFA enrollment found")
}

func TestSetIDPClientsMFA(t *testing.T) {
	ctx := context.Background()
	st := newTestIDPStorage(t)

	require.NoError(t, setIDPClientsMFA(ctx, st, true))
	status, err := idpClientsMFAStatus(ctx, st)
	require.NoError(t, err)
	require.Equal(t, "enabled", status)

	require.NoError(t, setIDPClientsMFA(ctx, st, false))
	status, err = idpClientsMFAStatus(ctx, st)
	require.NoError(t, err)
	require.Equal(t, "disabled", status)
}

func newTestManagementStore(t *testing.T, localMFAEnabled bool) mgmtstore.Store {
	t.Helper()
	ctx := context.Background()
	st, err := mgmtstore.NewStore(ctx, types.SqliteStoreEngine, t.TempDir(), nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close(ctx)) })
	require.NoError(t, st.SaveAccount(ctx, &types.Account{
		Id:       "account-1",
		Settings: &types.Settings{LocalMfaEnabled: localMFAEnabled},
	}))
	return st
}

func TestRunSetMFAEnabledDoesNotSaveWhenIDPUpdateFails(t *testing.T) {
	ctx := context.Background()
	managementStore := newTestManagementStore(t, false)
	idpStorage := memory.New(slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := runSetMFAEnabled(ctx, Resources{Store: managementStore, IDPStorage: idpStorage}, io.Discard, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "embedded IdP client")

	settings, err := managementStore.GetAccountSettings(ctx, mgmtstore.LockingStrengthNone, "account-1")
	require.NoError(t, err)
	require.False(t, settings.LocalMfaEnabled)
}

func TestRunSetMFAEnabledUpdatesSettingsAfterIDP(t *testing.T) {
	ctx := context.Background()
	managementStore := newTestManagementStore(t, false)
	idpStorage := newTestIDPStorage(t)

	err := runSetMFAEnabled(ctx, Resources{Store: managementStore, IDPStorage: idpStorage}, io.Discard, true)
	require.NoError(t, err)

	settings, err := managementStore.GetAccountSettings(ctx, mgmtstore.LockingStrengthNone, "account-1")
	require.NoError(t, err)
	require.True(t, settings.LocalMfaEnabled)
	clientStatus, err := idpClientsMFAStatus(ctx, idpStorage)
	require.NoError(t, err)
	require.Equal(t, "enabled", clientStatus)
}

func TestRunSetMFAEnabledSucceedsWithNilEventStore(t *testing.T) {
	ctx := context.Background()
	managementStore := newTestManagementStore(t, false)
	idpStorage := newTestIDPStorage(t)
	var out bytes.Buffer
	var err error

	require.NotPanics(t, func() {
		err = runSetMFAEnabled(ctx, Resources{Store: managementStore, IDPStorage: idpStorage, EventStore: nil}, &out, true)
	})
	require.NoError(t, err)
	require.Contains(t, out.String(), "Local MFA enabled")

	settings, err := managementStore.GetAccountSettings(ctx, mgmtstore.LockingStrengthNone, "account-1")
	require.NoError(t, err)
	require.True(t, settings.LocalMfaEnabled)
}

func TestUserSelectorValidate(t *testing.T) {
	require.NoError(t, userSelector{email: " user@example.com "}.validate())
	require.NoError(t, userSelector{userID: "user-1"}.validate())
	require.Error(t, userSelector{}.validate())
	require.Error(t, userSelector{email: "user@example.com", userID: "user-1"}.validate())
}

func TestFindLocalUserNotFound(t *testing.T) {
	st := newTestIDPStorage(t)
	_, err := findLocalUser(context.Background(), st, userSelector{email: "missing@example.com"}, "")
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "not found"))
}

func TestFindLocalUserZeroUsersIncludesStoragePath(t *testing.T) {
	st := memory.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := findLocalUser(context.Background(), st, userSelector{email: "missing@example.com"}, "/var/lib/netbird/idp.db")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no local users exist")
	require.Contains(t, err.Error(), "/var/lib/netbird/idp.db")
}

func TestUserCommandValidatesSelectorBeforeOpeningStorage(t *testing.T) {
	opened := false
	cmd := NewCommands(Openers{
		IDP: func(cmd *cobra.Command, fn func(ctx context.Context, idpStorage storage.Storage, storageFile string) error) error {
			opened = true
			return nil
		},
	})
	cmd.SetArgs([]string{"user", "change-password", "--password", "NewPass1!"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "provide exactly one")
	require.False(t, opened)
}

func TestResolvePasswordInputFromStdin(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("NewPass1!\n"))

	password, err := resolvePasswordInput(cmd, "", "-")
	require.NoError(t, err)
	require.Equal(t, "NewPass1!", password)
}

func TestResolvePasswordInputRejectsMultipleSources(t *testing.T) {
	_, err := resolvePasswordInput(&cobra.Command{}, "NewPass1!", "-")
	require.Error(t, err)
}
