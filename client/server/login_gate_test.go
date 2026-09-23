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
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:       filepath.Join(profilemanager.DefaultConfigPathDir, target+".json"),
		ManagementURL:    "https://api.netbird.io:443",
		ServerSSHAllowed: boolPtr(true),
	})
	require.NoError(t, err)

	_, err = s.Login(userCtx(), &proto.LoginRequest{
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

	_, err = s.Login(userCtx(), &proto.LoginRequest{
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

	stored, err := profilemanager.ReadConfig(targetPath)
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
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:       filepath.Join(profilemanager.DefaultConfigPathDir, target+".json"),
		ManagementURL:    "https://api.netbird.io:443",
		ServerSSHAllowed: boolPtr(true),
	})
	require.NoError(t, err)

	cancelled := false
	s.actCancel = func() { cancelled = true }

	_, err = s.Login(userCtx(), &proto.LoginRequest{
		ProfileName:   &target,
		Username:      &username,
		ManagementUrl: "https://mgmt.attacker.example:443",
	})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, gstatus.Code(err), "want a privilege refusal, got %v", err)
	require.False(t, cancelled, "the refused login cancelled the login already in progress")
}
