package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// enableSSHOnProfile rewrites the profile config at cfgPath with the SSH server
// enabled. Deregistering an SSH-enabled profile is a privileged change, so an
// unprivileged caller is refused by requirePrivilegeForDeregistration before any
// management connection is attempted — which is what keeps these tests offline.
func enableSSHOnProfile(t *testing.T, cfgPath string) {
	t.Helper()
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:       cfgPath,
		ManagementURL:    "https://api.netbird.io:443",
		ServerSSHAllowed: boolPtr(true),
	})
	require.NoError(t, err)
}

// Logging out of the profile the daemon is already running is a deregistration,
// not profile management, so the profiles-disabled kill switch must not block
// it. The desktop UI always addresses logout by profile (both the profile menu
// and the session-expiration dialog), so gating it left users with
// disableProfiles enforced unable to log out at all.
func TestLogout_ActiveProfileAllowedWhenProfilesDisabled(t *testing.T) {
	s, _, activeProfile, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())
	enableSSHOnProfile(t, cfgPath)

	s.profilesDisabled = true

	_, err := s.Logout(userCtx(), &proto.LogoutRequest{
		ProfileName: &activeProfile,
		Username:    &username,
	})

	require.Error(t, err, "the SSH privilege gate is expected to refuse this unprivileged caller")
	require.Equal(t, codes.PermissionDenied, gstatus.Code(err),
		"logout of the active profile must reach the deregistration path, not be refused as profile management: %v", err)
	require.NotContains(t, gstatus.Convert(err).Message(), errProfilesDisabled)
}

// A profile-addressed logout that targets some *other* profile does manage
// profiles, so it stays gated: with profiles disabled the daemon must not
// deregister a peer the user is not currently running.
func TestLogout_OtherProfileStaysGatedWhenProfilesDisabled(t *testing.T) {
	s, _, _, username, _ := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())

	other := "other-profile"
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(profilemanager.DefaultConfigPathDir, other+".json"),
		ManagementURL: "https://api.netbird.io:443",
	})
	require.NoError(t, err)

	s.profilesDisabled = true

	_, err = s.Logout(userCtx(), &proto.LogoutRequest{
		ProfileName: &other,
		Username:    &username,
	})

	require.Error(t, err)
	require.Equal(t, codes.Unavailable, gstatus.Code(err), "want the profiles-disabled refusal, got %v", err)
	require.Contains(t, gstatus.Convert(err).Message(), errProfilesDisabled)
}

// With profiles enabled the gate is out of the way on both surfaces; the active
// profile still reaches the deregistration path.
func TestLogout_ActiveProfileAllowedWhenProfilesEnabled(t *testing.T) {
	s, _, activeProfile, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())
	enableSSHOnProfile(t, cfgPath)

	_, err := s.Logout(userCtx(), &proto.LogoutRequest{
		ProfileName: &activeProfile,
		Username:    &username,
	})

	require.Error(t, err, "the SSH privilege gate is expected to refuse this unprivileged caller")
	require.Equal(t, codes.PermissionDenied, gstatus.Code(err), "want the privilege refusal, got %v", err)
}
