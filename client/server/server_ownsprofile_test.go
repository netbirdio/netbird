package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Resolving a handle claims every legacy profile the caller can take, the
// active one included, whatever profile the handle itself names. SessionHolder
// answers from the daemon's in-memory config, so OwnsProfile has to refresh it
// for any handle: a copy taken before the claim reports no owner at all, and a
// session with no owner is one every identified caller may take over.
func TestOwnsProfile_RefreshesActiveConfigForAnyHandle(t *testing.T) {
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

			require.True(t, s.OwnsProfile(owner, tc.handle), "the caller owns every profile in this fixture")

			holder, running := s.SessionHolder()
			require.True(t, running, "the claimed owner never reached the daemon's config, so the live session is unowned")
			require.True(t, holder.Matches(owner), "the session is held by %v, not by the profile's owner", holder)
		})
	}
}

// A caller whose profile the daemon cannot read is not the owner of anything.
// The answer has to be no rather than a panic in the authorization path.
func TestOwnsProfile_UnreadableActiveProfileStateDenies(t *testing.T) {
	s, _, _, _, _ := setupServerWithProfile(t)

	require.NoError(t, os.WriteFile(profilemanager.ActiveProfileStatePath, []byte("{"), 0600))

	require.False(t, s.OwnsProfile(unprivilegedIdentity(), ""))
}

// A config the daemon cannot re-read leaves the one it already has in place.
// Dropping a nil in its stead would take down every reader of it, SessionHolder
// among them, which is the authorization path itself.
func TestOwnsProfile_UnreadableConfigKeepsTheOneInPlace(t *testing.T) {
	s, _, _, _, _ := setupServerWithProfile(t)

	// An ID no path can be built for, which is what a hand-edited or
	// downgrade-written state file can leave behind.
	require.NoError(t, os.WriteFile(profilemanager.ActiveProfileStatePath, []byte(`{"name":"../escape"}`), 0600))

	kept := &profilemanager.Config{Owners: []string{ipcauth.OwnerPrincipalForIdentity(unprivilegedIdentity())}}
	s.config = kept
	s.clientRunning = true

	require.False(t, s.OwnsProfile(unprivilegedIdentity(), ""))
	require.Same(t, kept, s.config, "a failed reload replaced the daemon's config")

	holder, running := s.SessionHolder()
	require.True(t, running)
	require.True(t, holder.Matches(unprivilegedIdentity()))
}

// A profile switch can land while the gate is still resolving: the resolution
// reads every profile off disk, and SwitchProfile only needs the daemon lock,
// which the gate does not hold. The config the reload publishes has to be the
// one the daemon is now on, not the one the check started out reading.
func TestOwnsProfile_ReloadFollowsASwitchThatLandsMidCheck(t *testing.T) {
	s, _, activeProfile, _, _ := setupServerWithProfile(t)
	owner := unprivilegedIdentity()

	switchedTo := "switched-to"
	switchedToURL := "https://switched-to.example:443"
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(profilemanager.DefaultConfigPathDir, switchedTo+".json"),
		ManagementURL: switchedToURL,
		Owner:         &owner,
	})
	require.NoError(t, err)

	s.config = &profilemanager.Config{}
	s.clientRunning = true

	// Stand in for a SwitchProfile that lands between the resolution and the
	// reload, which is the whole window the profile files are being read in.
	afterProfileResolve = func() {
		require.NoError(t, s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
			ID: profilemanager.ID(switchedTo),
		}))
	}
	t.Cleanup(func() { afterProfileResolve = nil })

	require.True(t, s.OwnsProfile(owner, activeProfile))

	require.NotNil(t, s.config.ManagementURL)
	require.Equal(t, switchedToURL, s.config.ManagementURL.String(),
		"the reload published the config of a profile the daemon had already left")
}

// The handlers that start a session read their config off disk themselves.
func TestOwnsProfile_IdleDaemonKeepsItsConfig(t *testing.T) {
	s, _, activeProfile, _, _ := setupServerWithProfile(t)

	untouched := &profilemanager.Config{}
	s.config = untouched
	s.clientRunning = false

	require.True(t, s.OwnsProfile(unprivilegedIdentity(), activeProfile))
	require.Same(t, untouched, s.config)
}
