package profilemanager

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// currentUserPrincipal returns the running account's name and the owner
// principal migration should record for it. Migration resolves a real account
// through the host's user database, so there is nothing to stub.
func currentUserPrincipal(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the windows path records a SID rather than a numeric uid")
	}

	u, err := user.Current()
	require.NoError(t, err)
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	require.NoError(t, err)

	return u.Username, "uid:" + strconv.FormatUint(uid, 10)
}

func TestMigrate_StampsTheActiveAccountsDirectory(t *testing.T) {
	username, principal := currentUserPrincipal(t)

	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		dir := sanitizeProfileName(username)
		mine := writeLegacyProfile(t, configDir, dir, "work", nil)
		theirs := writeLegacyProfile(t, configDir, "someone-else", "theirs", nil)
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "work", Username: username}))

		require.NoError(t, sm.MigrateLegacyProfiles())

		assert.Equal(t, []string{principal}, readOwners(t, mine))
		assert.Empty(t, readOwners(t, theirs),
			"only the account the active state names has a directory we can attribute")
		assert.DirExists(t, filepath.Join(configDir, DefaultProfilePathDir),
			"the marker is written once both halves are done")
	})
}

func TestMigrate_IsIdempotentAndSkipsOnceMarked(t *testing.T) {
	username, principal := currentUserPrincipal(t)

	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, sanitizeProfileName(username), "work", nil)
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "work", Username: username}))

		require.NoError(t, sm.MigrateLegacyProfiles())
		require.NoError(t, sm.MigrateLegacyProfiles())
		assert.Equal(t, []string{principal}, readOwners(t, path))

		// A profile appearing after the marker is left to the per-caller claim.
		late := writeLegacyProfile(t, configDir, sanitizeProfileName(username), "late", nil)
		require.NoError(t, sm.MigrateLegacyProfiles())
		assert.Empty(t, readOwners(t, late))
	})
}

func TestMigrate_RekeysDuplicateIDsAndKeepsTheActiveOne(t *testing.T) {
	username, principal := currentUserPrincipal(t)

	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		dir := sanitizeProfileName(username)
		writeLegacyProfile(t, configDir, dir, "work", nil)
		writeLegacyProfile(t, configDir, "someone-else", "work", nil)
		require.NoError(t, os.WriteFile(filepath.Join(configDir, dir, "work"+stateFileSuffix), []byte("{}"), 0600))
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "work", Username: username}))

		require.NoError(t, sm.MigrateLegacyProfiles())

		profiles, err := sm.loadAllProfiles()
		require.NoError(t, err)

		ids := map[ID]int{}
		for _, p := range profiles {
			ids[p.ID]++
			if p.ID != defaultProfileName {
				assert.Equal(t, "work", p.Name, "the display name outlives the filename it came from")
			}
		}
		for id, n := range ids {
			assert.Equal(t, 1, n, "%s is still shared after migration", id)
		}

		state, err := sm.GetActiveProfileState()
		require.NoError(t, err)
		assert.NotEqual(t, ID("work"), state.ID, "the active profile follows its new ID")

		active, err := sm.ActiveProfilePath(state)
		require.NoError(t, err)
		assert.Equal(t, dir, filepath.Base(filepath.Dir(active)),
			"and still resolves inside the account that was running it")
		assert.Equal(t, []string{principal}, readOwners(t, active))
		assert.FileExists(t, filepath.Join(configDir, dir, state.ID.String()+stateFileSuffix),
			"the state file follows the profile it belongs to")
	})
}

func TestMigrate_UnresolvableAccountLeavesNoMarker(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "ghost", "work", nil)
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{
			ID: "work", Username: "no-such-account-here",
		}))

		require.Error(t, sm.MigrateLegacyProfiles())
		assert.Empty(t, readOwners(t, path))
		assert.NoDirExists(t, filepath.Join(configDir, DefaultProfilePathDir),
			"an unfinished run leaves no marker, so the next start tries again")
	})
}
