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
		ConnectorID: localConnectorID,
		MFASecrets: map[string]*storage.MFASecret{
			defaultTOTPAuthenticatorID: {
				AuthenticatorID: defaultTOTPAuthenticatorID,
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
		ConnectorID: localConnectorID,
		Nonce:       "nonce",
	}))
	require.NoError(t, st.CreateClient(context.Background(), storage.Client{ID: cliClientID, Name: "CLI"}))
	require.NoError(t, st.CreateClient(context.Background(), storage.Client{ID: dashboardClientID, Name: "Dashboard"}))

	return st
}

func TestRunChangePassword(t *testing.T) {
	ctx := context.Background()
	st := newTestIDPStorage(t)
	var out bytes.Buffer

	err := runChangePassword(ctx, st, &out, userSelector{email: "user@example.com"}, "NewPass1!")
	require.NoError(t, err)
	require.Contains(t, out.String(), "Password updated")

	user, err := st.GetPassword(ctx, "user@example.com")
	require.NoError(t, err)
	require.NoError(t, bcrypt.CompareHashAndPassword(user.Hash, []byte("NewPass1!")))

	_, err = st.GetAuthSession(ctx, "user-1", localConnectorID)
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestRunChangePasswordValidatesPassword(t *testing.T) {
	st := newTestIDPStorage(t)
	err := runChangePassword(context.Background(), st, io.Discard, userSelector{email: "user@example.com"}, "short")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid password")
}

func TestRunResetMFA(t *testing.T) {
	ctx := context.Background()
	st := newTestIDPStorage(t)
	var out bytes.Buffer

	encodedUserID := nbdex.EncodeDexUserID("user-1", localConnectorID)
	err := runResetMFA(ctx, st, &out, userSelector{userID: encodedUserID})
	require.NoError(t, err)
	require.Contains(t, out.String(), "MFA reset")

	identity, err := st.GetUserIdentity(ctx, "user-1", localConnectorID)
	require.NoError(t, err)
	require.Empty(t, identity.MFASecrets)
	require.Empty(t, identity.WebAuthnCredentials)

	_, err = st.GetAuthSession(ctx, "user-1", localConnectorID)
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestRunResetMFAWithoutEnrollment(t *testing.T) {
	ctx := context.Background()
	st := newTestIDPStorage(t)
	require.NoError(t, st.UpdateUserIdentity(ctx, "user-1", localConnectorID, func(old storage.UserIdentity) (storage.UserIdentity, error) {
		old.MFASecrets = nil
		old.WebAuthnCredentials = nil
		return old, nil
	}))

	var out bytes.Buffer
	err := runResetMFA(ctx, st, &out, userSelector{email: "user@example.com"})
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

func TestUserSelectorValidate(t *testing.T) {
	require.NoError(t, userSelector{email: " user@example.com "}.validate())
	require.NoError(t, userSelector{userID: "user-1"}.validate())
	require.Error(t, userSelector{}.validate())
	require.Error(t, userSelector{email: "user@example.com", userID: "user-1"}.validate())
}

func TestFindLocalUserNotFound(t *testing.T) {
	st := newTestIDPStorage(t)
	_, err := findLocalUser(context.Background(), st, userSelector{email: "missing@example.com"})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "not found"))
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
