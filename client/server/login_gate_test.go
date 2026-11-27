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

// A refused login must not leave the profile switched. Login can both switch
// profiles and carry the guarded config fields, so the gate has to run before the
// switch: otherwise a caller whose change is refused still gets the side effect of
// activating whichever profile the request named.
func TestLogin_RefusedChangeLeavesTheProfileAlone(t *testing.T) {
	s, _, activeProfile, username, _ := setupServerWithProfile(t)

	// Login reads process state off the daemon's root context.
	s.rootCtx = internal.CtxInitState(context.Background())

	// A second profile that runs the SSH server, which is what makes repointing
	// its management binding a privileged change.
	target := "ssh-enabled"
	targetPath := filepath.Join(profilemanager.DefaultConfigPathDir, target+".json")
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:       targetPath,
		ManagementURL:    "https://api.netbird.io:443",
		ServerSSHAllowed: boolPtr(true),
		Owner:            testProfileOwner(),
	})
	require.NoError(t, err)

	_, err = s.Login(withTarget(userCtx(), targetPath), &proto.LoginRequest{
		ProfileName:   &target,
		Username:      &username,
		ManagementUrl: "https://mgmt.attacker.example:443",
	})
	require.Error(t, err, "an unprivileged caller must not move the management URL of an SSH-enabled profile")
	require.Equal(t, codes.PermissionDenied, gstatus.Code(err), "want a privilege refusal, got %v", err)

	active, err := s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	require.Equal(t, profilemanager.ID(activeProfile), active.ID,
		"the refused login switched the active profile anyway")
}

// A caller whose change becomes privileged only after its first check must be
// refused without having cancelled a login or switched profiles: the first check is
// unsynchronized, so the SSH server can be enabled by a concurrent privileged
// request in between, and the authoritative check happens before any side effect.
func TestLogin_ChangeThatBecomesPrivilegedMidRequestHasNoSideEffects(t *testing.T) {
	s, _, activeProfile, username, _ := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())

	// The target profile has SSH off, so the first check lets the request through.
	target := "ssh-later"
	targetPath := filepath.Join(profilemanager.DefaultConfigPathDir, target+".json")
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:       targetPath,
		ManagementURL:    "https://api.netbird.io:443",
		ServerSSHAllowed: boolPtr(false),
		Owner:            testProfileOwner(),
	})
	require.NoError(t, err)

	cancelled := false
	s.actCancel = func() { cancelled = true }

	// Stand in for a privileged SetConfig that enables the SSH server between the
	// two checks, which is the interleaving the lock has to make safe.
	afterLoginPreCheck = func() {
		_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
			ConfigPath:       targetPath,
			ServerSSHAllowed: boolPtr(true),
		})
		require.NoError(t, err)
	}
	t.Cleanup(func() { afterLoginPreCheck = nil })

	_, err = s.Login(withTarget(userCtx(), targetPath), &proto.LoginRequest{
		ProfileName:   &target,
		Username:      &username,
		ManagementUrl: "https://mgmt.attacker.example:443",
	})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, gstatus.Code(err), "want a privilege refusal, got %v", err)
	require.False(t, cancelled, "the refused login cancelled the login already in progress")

	active, err := s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	require.Equal(t, profilemanager.ID(activeProfile), active.ID, "the refused login switched the active profile anyway")

	stored, err := profilemanager.GetExistingConfig(targetPath)
	require.NoError(t, err)
	require.Equal(t, "https://api.netbird.io:443", stored.ManagementURL.String(), "the refused login moved the management URL")
}

// Login cancels whatever login is already in progress before starting its own. A
// refused caller must not get that far, otherwise anyone able to reach the socket
// can abort someone else's login by sending a request that is denied.
func TestLogin_RefusedChangeLeavesAnInProgressLoginAlone(t *testing.T) {
	s, _, _, username, _ := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())

	target := "ssh-enabled"
	targetPath := filepath.Join(profilemanager.DefaultConfigPathDir, target+".json")
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:       targetPath,
		ManagementURL:    "https://api.netbird.io:443",
		ServerSSHAllowed: boolPtr(true),
		Owner:            testProfileOwner(),
	})
	require.NoError(t, err)

	cancelled := false
	s.actCancel = func() { cancelled = true }

	_, err = s.Login(withTarget(userCtx(), targetPath), &proto.LoginRequest{
		ProfileName:   &target,
		Username:      &username,
		ManagementUrl: "https://mgmt.attacker.example:443",
	})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, gstatus.Code(err), "want a privilege refusal, got %v", err)
	require.False(t, cancelled, "the refused login cancelled the login already in progress")
}

// A login that names no profile is approved for the profile active when the gate
// ran. A switch that lands before the write must not redirect the write to the
// newly active profile, which neither the gate nor the privilege check looked at.
func TestLogin_SwitchMidRequestDoesNotRedirectTheWrite(t *testing.T) {
	s, _, _, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())
	s.isLoginRequiredFn = func(context.Context) (bool, error) { return false, nil }

	// Another user's profile that runs the SSH server.
	victim := "victim"
	victimPath := filepath.Join(profilemanager.DefaultConfigPathDir, victim+".json")
	victimOwner := privilegedIdentity()
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:       victimPath,
		ManagementURL:    "https://api.netbird.io:443",
		ServerSSHAllowed: boolPtr(true),
		Owner:            &victimOwner,
	})
	require.NoError(t, err)

	// The victim switches to their profile after the caller's first check.
	afterLoginPreCheck = func() {
		require.NoError(t, s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
			ID:       profilemanager.ID(victim),
			Username: username,
		}))
	}
	t.Cleanup(func() { afterLoginPreCheck = nil })

	_, err = s.Login(withTarget(userCtx(), cfgPath), &proto.LoginRequest{
		Username:      &username,
		ManagementUrl: "https://mgmt.attacker.example:443",
	})
	require.Error(t, err)
	require.Equal(t, codes.Aborted, gstatus.Code(err), "want a retryable refusal, got %v", err)

	stored, err := profilemanager.GetExistingConfig(victimPath)
	require.NoError(t, err)
	require.Equal(t, "https://api.netbird.io:443", stored.ManagementURL.String(),
		"the login wrote to a profile the gate never approved")
}

// Another user's Up can switch profiles and start its session after the login's
// active profile check. The login must not then install its own profile's
// config, because SessionHolder reads the session's owner from it.
func TestLogin_SwitchAfterTheCheckKeepsTheRunningProfilesConfig(t *testing.T) {
	s, _, _, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())
	s.isLoginRequiredFn = func(context.Context) (bool, error) { return false, nil }

	victim := "victim"
	victimPath := filepath.Join(profilemanager.DefaultConfigPathDir, victim+".json")
	victimOwner := privilegedIdentity()
	victimCfg, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    victimPath,
		ManagementURL: "https://api.netbird.io:443",
		Owner:         &victimOwner,
	})
	require.NoError(t, err)

	// Stands in for the victim's Up, which switches and installs its config
	// under s.mutex.
	afterLoginPrepared = func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		require.NoError(t, s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
			ID:       profilemanager.ID(victim),
			Username: username,
		}))
		s.config = victimCfg
		s.clientRunning = true
	}
	t.Cleanup(func() { afterLoginPrepared = nil })

	_, err = s.Login(withTarget(userCtx(), cfgPath), &proto.LoginRequest{Username: &username})

	holder, held := s.SessionHolder()
	require.True(t, held, "the victim's session must still be held")
	require.True(t, holder.Matches(victimOwner), "the login made its own caller the holder of the victim's session")

	require.Error(t, err)
	require.Equal(t, codes.Aborted, gstatus.Code(err), "want a retryable refusal, got %v", err)
}
