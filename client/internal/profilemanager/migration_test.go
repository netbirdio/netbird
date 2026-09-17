package profilemanager

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

// failRenamesOf makes every rename of a file with the given suffix fail, and
// returns the function that lets them through again.
func failRenamesOf(t *testing.T, suffix string) func() {
	t.Helper()

	orig := renameFile
	failing := true
	renameFile = func(from, to string) error {
		if failing && strings.HasSuffix(from, suffix) {
			return errors.New("simulated rename failure")
		}
		return orig(from, to)
	}
	t.Cleanup(func() { renameFile = orig })

	return func() { failing = false }
}

func TestMigrate_AStateFileThatCannotFollowRollsBackTheRekey(t *testing.T) {
	username, _ := currentUserPrincipal(t)

	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		dir := sanitizeProfileName(username)
		mine := writeLegacyProfile(t, configDir, dir, "work", nil)
		writeLegacyProfile(t, configDir, "someone-else", "work", nil)
		state := filepath.Join(configDir, dir, "work"+stateFileSuffix)
		require.NoError(t, os.WriteFile(state, []byte("{}"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(configDir, dir, "work"+prefsFileSuffix), []byte("{}"), 0600))
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "work", Username: username}))

		allowRenames := failRenamesOf(t, prefsFileSuffix)

		require.Error(t, sm.MigrateLegacyProfiles())
		assert.NoDirExists(t, filepath.Join(configDir, DefaultProfilePathDir),
			"a rekey that could not finish leaves no marker, so the next start tries again")
		assert.FileExists(t, mine, "the profile is back under the ID its state file still carry")
		assert.FileExists(t, state, "and so is the state file that had already moved")

		// The next start finds the profile exactly as the failed one did, and
		// the state file are still beside it once the rekey goes through.
		allowRenames()
		require.NoError(t, sm.MigrateLegacyProfiles())

		profiles, err := sm.loadAllProfiles()
		require.NoError(t, err)

		ids := map[ID]int{}
		var rolledBack *Profile
		for i := range profiles {
			p := &profiles[i]
			ids[p.ID]++
			if p.ID != defaultProfileName && filepath.Dir(p.Path) == filepath.Join(configDir, dir) {
				rolledBack = p
			}
		}
		for id, n := range ids {
			assert.Equal(t, 1, n, "%s is still shared after migration", id)
		}

		require.NotNil(t, rolledBack)
		for _, suffix := range []string{stateFileSuffix, prefsFileSuffix} {
			assert.FileExists(t, filepath.Join(configDir, dir, rolledBack.ID.String()+suffix),
				"%s follows the profile it belongs to", suffix)
		}
	})
}

func TestMigrate_NamesakesTheStateCannotTellApartLeaveNoMarker(t *testing.T) {
	username, _ := currentUserPrincipal(t)

	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		dir := sanitizeProfileName(username)
		mine := writeLegacyProfile(t, configDir, dir, "work", nil)
		theirs := writeLegacyProfile(t, configDir, "someone-else", "work", nil)
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "work"}))

		require.ErrorIs(t, sm.MigrateLegacyProfiles(), ErrAmbiguousActiveProfile)
		assert.NoDirExists(t, filepath.Join(configDir, DefaultProfilePathDir),
			"the marker would retire the only pass that can still separate them")
		assert.FileExists(t, mine, "so both namesakes are left as they are")
		assert.FileExists(t, theirs)

		profiles, err := sm.loadAllProfiles()
		require.NoError(t, err)
		assert.Equal(t, 2, countID(profiles, "work"),
			"the group keeps the ID, since rekeying it would leave the state pointing at nothing")

		// And until they are separated the active profile does not resolve to
		// whichever of them happened to sort first.
		state, err := sm.GetActiveProfileState()
		require.NoError(t, err)
		_, err = sm.ActiveProfilePath(state)
		require.ErrorIs(t, err, ErrAmbiguousActiveProfile)

		// Selecting a profile records the directory that tells them apart, and
		// the start after that finishes the job.
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "work", Username: username}))
		require.NoError(t, sm.MigrateLegacyProfiles())
		assert.DirExists(t, filepath.Join(configDir, DefaultProfilePathDir))

		state, err = sm.GetActiveProfileState()
		require.NoError(t, err)
		active, err := sm.ActiveProfilePath(state)
		require.NoError(t, err)
		assert.NotEqual(t, ID("work"), state.ID, "the namesakes are separated")
		assert.Equal(t, dir, filepath.Base(filepath.Dir(active)),
			"and the active one still sits in the account that was running it")
	})
}

// countID reports how many of the loaded profiles hold id.
func countID(profiles []Profile, id ID) int {
	n := 0
	for _, p := range profiles {
		if p.ID == id {
			n++
		}
	}
	return n
}

func TestMigrate_LeavesAProfileThatAlreadyNamesAnOwnerAlone(t *testing.T) {
	username, principal := currentUserPrincipal(t)

	// A SID is never what a Unix host stamps, so it says "someone else holds
	// this" without depending on the uid the test happens to run as.
	const otherOwner = "sid:S-1-5-21-0-0-0-1001"

	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		dir := sanitizeProfileName(username)
		claimed := writeLegacyProfile(t, configDir, dir, "claimed", map[string]any{
			"Owners": []string{otherOwner},
		})
		unclaimed := writeLegacyProfile(t, configDir, dir, "unclaimed", nil)
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "unclaimed", Username: username}))

		require.NoError(t, sm.MigrateLegacyProfiles())

		assert.Equal(t, []string{otherOwner}, readOwners(t, claimed),
			"the directory a profile sits in does not re-attribute one that already names an owner")
		assert.Equal(t, []string{principal}, readOwners(t, unclaimed),
			"only the profiles with no owner of their own are attributed")
	})
}

func TestMigrate_SkipsAProfileItCannotStamp(t *testing.T) {
	username, principal := currentUserPrincipal(t)

	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		dir := sanitizeProfileName(username)
		good := writeLegacyProfile(t, configDir, dir, "work", nil)
		broken := filepath.Join(configDir, dir, "broken.json")
		require.NoError(t, os.WriteFile(broken, []byte("null"), 0600))
		require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "work", Username: username}))

		require.NoError(t, sm.MigrateLegacyProfiles())

		assert.Equal(t, []string{principal}, readOwners(t, good),
			"one profile that cannot be stamped does not hold up the rest")
		assert.DirExists(t, filepath.Join(configDir, DefaultProfilePathDir),
			"and the marker still lands, since the claim path retries the one left behind")

		data, err := os.ReadFile(broken)
		require.NoError(t, err)
		assert.Equal(t, "null", string(data), "the profile it could not stamp is untouched")
	})
}
