package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// unreachableManagementURL keeps a test that is expected to stop at a gate from
// reaching the network if the gate ever regresses: the profiles a logout must
// not touch point here, so a leak fails fast instead of contacting a real
// management server.
const unreachableManagementURL = "https://127.0.0.1:9"

// enableSSHOnProfile rewrites the profile config at cfgPath with the SSH server
// enabled. Deregistering an SSH-enabled profile is a privileged change, so an
// unprivileged caller is refused by requirePrivilegeForDeregistration before any
// management connection is attempted, which is what keeps these tests offline.
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
		ManagementURL: unreachableManagementURL,
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

// A legacy profile ID is a display name, so two users can hold the same ID in
// their own profile directories. Matching on the ID alone would let one user's
// logout pass the gate against the other user's active profile, so the username
// is part of the comparison.
func TestLogout_ForeignUserProfileStaysGatedWhenProfilesDisabled(t *testing.T) {
	s, _, _, username, _ := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())

	// A legacy-style profile whose ID is its filename stem, and an active state
	// claiming that same ID for a different user.
	shared := "shared-legacy-name"
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(profilemanager.DefaultConfigPathDir, shared+".json"),
		ManagementURL: unreachableManagementURL,
	})
	require.NoError(t, err)
	require.NoError(t, s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       profilemanager.ID(shared),
		Username: "someone-else",
	}))

	s.profilesDisabled = true

	_, err = s.Logout(userCtx(), &proto.LogoutRequest{
		ProfileName: &shared,
		Username:    &username,
	})

	require.Error(t, err)
	require.Equal(t, codes.Unavailable, gstatus.Code(err),
		"another user's profile must not pass the gate on an ID match alone: %v", err)
}

// Deregistering a namesake profile must not go out with the running config.
// logoutFromProfile reuses the connected client's config when the target is the
// active profile, and on an ID-only match a shared legacy ID made it reuse it
// for another user's profile, deregistering the active peer instead.
func TestLogout_ForeignUserProfileDoesNotUseTheRunningConfig(t *testing.T) {
	s, _, _, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())

	// The running config has the SSH server enabled, so reusing it would be
	// refused with PermissionDenied. The namesake profile does not, so the
	// correct path gets as far as dialing its own unreachable management URL.
	enableSSHOnProfile(t, cfgPath)
	running, err := profilemanager.GetConfig(cfgPath)
	require.NoError(t, err)
	s.config = running
	s.connectClient = newDummyConnectClient(context.Background())

	shared := "shared-legacy-name"
	_, err = profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(profilemanager.DefaultConfigPathDir, shared+".json"),
		ManagementURL: unreachableManagementURL,
	})
	require.NoError(t, err)
	require.NoError(t, s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       profilemanager.ID(shared),
		Username: "someone-else",
	}))

	// Bounded so the deregistration the fixed path attempts fails on the dial
	// rather than sitting in gRPC backoff for the whole test timeout.
	ctx, cancel := context.WithTimeout(userCtx(), 2*time.Second)
	t.Cleanup(cancel)

	_, err = s.Logout(ctx, &proto.LogoutRequest{
		ProfileName: &shared,
		Username:    &username,
	})

	require.Error(t, err)
	require.NotEqual(t, codes.PermissionDenied, gstatus.Code(err),
		"the namesake profile was deregistered with the running config: %v", err)
}

// The connection teardown follows the profile that is active when the logout
// completes, not the one seen before it started: Login switches profiles under
// guardedConfigMu, which the logout path does not hold, so a login that landed
// meanwhile must keep its connection.
func TestCleanupAfterProfileLogout_FollowsTheCurrentActiveProfile(t *testing.T) {
	s, _, activeProfile, username, _ := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())

	state := internal.CtxGetState(s.rootCtx)

	s.cleanupAfterProfileLogout("some-other-profile", username)
	status, err := state.Status()
	require.NoError(t, err)
	require.NotEqual(t, internal.StatusNeedsLogin, status,
		"logging out of a profile that is not active must not ask for a new login")

	s.cleanupAfterProfileLogout(profilemanager.ID(activeProfile), username)
	status, err = state.Status()
	require.NoError(t, err)
	require.Equal(t, internal.StatusNeedsLogin, status,
		"logging out of the active profile must ask for a new login")
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
