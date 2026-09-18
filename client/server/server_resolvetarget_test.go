package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Resolving a handle claims every legacy profile the caller can take, the
// active one included, whatever profile the handle itself names. SessionHolder
// answers from the daemon's in-memory config, so ResolveTarget has to refresh it
// for any handle.
func TestResolveTarget_RefreshesActiveConfigForAnyHandle(t *testing.T) {
	other := "second-profile"

	for _, tc := range []struct {
		name   string
		handle string
	}{
		{name: "no handle falls back to the active profile", handle: ""},
		{name: "the active profile by ID", handle: "test-profile-mdm"},
		{name: "another profile entirely", handle: other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, activeProfile, _, _ := setupServerWithProfile(t)
			require.Equal(t, "test-profile-mdm", activeProfile)

			owner := unprivilegedIdentity()
			_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
				ConfigPath:    filepath.Join(profilemanager.DefaultConfigPathDir, other+".json"),
				ManagementURL: "https://api.netbird.io:443",
				Owner:         &owner,
			})
			require.NoError(t, err)

			// The daemon's copy as it stood before the claim landed on disk.
			s.config = &profilemanager.Config{}
			s.clientRunning = true
			_, running := s.SessionHolder()
			require.False(t, running, "fixture is wrong: the stale copy already names an owner")

			target, err := s.ResolveTarget(owner, tc.handle)
			require.NoError(t, err)
			require.True(t, target.Owned, "the caller owns every profile in this fixture")

			holder, running := s.SessionHolder()
			require.True(t, running, "the claimed owner never reached the daemon's config, so the live session is unowned")
			require.True(t, holder.Matches(owner), "the session is held by %v, not by the profile's owner", holder)
		})
	}
}

// A caller whose profile the daemon cannot read is not the owner of anything.
// The answer has to be no rather than a panic in the authorization path.
func TestResolveTarget_UnreadableActiveProfileStateDenies(t *testing.T) {
	s, _, _, _, _ := setupServerWithProfile(t)

	require.NoError(t, os.WriteFile(profilemanager.ActiveProfileStatePath, []byte("{"), 0600))

	target, err := s.ResolveTarget(unprivilegedIdentity(), "")
	require.NoError(t, err, "an unreadable active profile is not the caller's handle to fix")
	require.False(t, target.Owned)
}

// A config the daemon cannot re-read leaves the one it already has in place.
func TestResolveTarget_UnreadableConfigKeepsTheOneInPlace(t *testing.T) {
	s, _, _, _, _ := setupServerWithProfile(t)

	// An ID no path can be built for, which is what a hand-edited or
	// downgrade-written state file can leave behind.
	require.NoError(t, os.WriteFile(profilemanager.ActiveProfileStatePath, []byte(`{"name":"../escape"}`), 0600))

	kept := &profilemanager.Config{Owners: []string{ipcauth.OwnerPrincipalForIdentity(unprivilegedIdentity())}}
	s.config = kept
	s.clientRunning = true

	target, err := s.ResolveTarget(unprivilegedIdentity(), "")
	require.NoError(t, err, "an active profile the daemon cannot place is not the caller's handle to fix")
	require.False(t, target.Owned, "a profile the caller does not own is nobody's to act on")
	require.Same(t, kept, s.config, "a failed reload replaced the daemon's config")

	holder, running := s.SessionHolder()
	require.True(t, running)
	require.True(t, holder.Matches(unprivilegedIdentity()))
}

// The handlers that start a session read their config off disk themselves.
func TestResolveTarget_IdleDaemonKeepsItsConfig(t *testing.T) {
	s, _, activeProfile, _, _ := setupServerWithProfile(t)

	untouched := &profilemanager.Config{}
	s.config = untouched
	s.clientRunning = false

	target, err := s.ResolveTarget(unprivilegedIdentity(), activeProfile)
	require.NoError(t, err)
	require.True(t, target.Owned)
	require.Same(t, untouched, s.config)
}

// foreignIdentity is a caller that is neither this process nor the one the test
// fixtures own profiles for, so a profile stamped for either is somebody else.
func foreignIdentity() ipcauth.Identity {
	if runtime.GOOS == "windows" {
		return ipcauth.KnownForTest(ipcauth.Identity{SID: "S-1-5-21-1-2-3-4242"})
	}
	return ipcauth.KnownForTest(ipcauth.Identity{UID: unprivUID + 1, GID: unprivUID + 1})
}

// Two accounts can hold the same legacy profile ID in their own directories,
// and a handle is resolved against every profile on the machine.
func TestResolveTarget_PrefersTheCallersOwnOverANamesake(t *testing.T) {
	s, _, _, _, _ := setupServerWithProfile(t)

	shared := "shared-legacy-name"
	ownPath := plantNamesakeProfiles(t, s, shared)

	target, err := s.ResolveTarget(unprivilegedIdentity(), shared)
	require.NoError(t, err, "another account's namesake must not make the handle ambiguous")
	require.True(t, target.Owned)
	require.Equal(t, ownPath, target.Path, "the handle resolved to the other account's profile")
}

// A profile that exists but belongs to somebody else resolves, so the refusal
// is about ownership rather than about the handle.
func TestResolveTarget_AnotherUsersProfileIsNotOwned(t *testing.T) {
	s, _, activeProfile, _, _ := setupServerWithProfile(t)

	target, err := s.ResolveTarget(foreignIdentity(), activeProfile)
	require.NoError(t, err, "the profile is there, so nothing about the handle is wrong")
	require.False(t, target.Owned, "a profile the caller does not own is not theirs to act on")
}

// Only a handle matching two of the caller's own profiles is genuinely
// ambiguous. Anything else has an answer, and the candidates named are theirs.
func TestResolveTarget_AmbiguousOnlyAmongTheCallersOwn(t *testing.T) {
	s, _, _, _, _ := setupServerWithProfile(t)

	shared := "shared-legacy-name"
	plantNamesakeProfiles(t, s, shared)

	// A second copy of the same ID in a directory this caller also claims,
	// which is the case no owner can settle.
	secondDir := filepath.Join(profilemanager.DefaultConfigPathDir, "second")
	require.NoError(t, os.MkdirAll(secondDir, 0700))
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(secondDir, shared+".json"),
		ManagementURL: "https://api.netbird.io:443",
		Owner:         testProfileOwner(),
	})
	require.NoError(t, err)

	_, err = s.ResolveTarget(unprivilegedIdentity(), shared)
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, gstatus.Code(err),
		"two profiles of the caller's own under one handle is theirs to disambiguate")
}
