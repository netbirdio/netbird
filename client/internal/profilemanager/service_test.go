package profilemanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/util"
)

// withTestSM wires up patched globals + a clean config dir and returns a
// fully initialized ServiceManager plus the identity we are scoped to.
func withTestSM(t *testing.T, fn func(sm *ServiceManager, id ipcauth.Identity)) {
	t.Helper()
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			require.NoError(t, sm.CreateDefaultProfile())

			userID, err := ipcauth.CurrentProcessIdentity()
			require.NoError(t, err)

			fn(sm, userID)
		})
	})
}

// The identity the helper hands out has to work as a profile owner on the
// platform the suite is running on.
// matchOne is the single profile a handle matches, for the tests that are about
// the matcher's precedence rather than about who is asking.
func matchOne(t *testing.T, sm *ServiceManager, handle string) Profile {
	t.Helper()

	match, err := sm.MatchProfiles(handle)
	require.NoError(t, err)
	require.Len(t, match.Profiles, 1, "handle %q did not match exactly one profile", handle)
	return match.Profiles[0]
}

// claimAndList is the sequence a request goes through now: the gate stamps
// whatever the caller can claim, and only then is the listing filtered by what
// they own. Listing on its own no longer claims.
func claimAndList(t *testing.T, sm *ServiceManager, id ipcauth.Identity) []Profile {
	t.Helper()

	sm.ClaimDefaultProfileIfNeeded(id)
	sm.ClaimLegacyProfiles(id)

	profiles, err := sm.ListProfiles(id)
	require.NoError(t, err)
	return profiles
}

func TestWithTestSM_ScopesToAUsableOwner(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, id ipcauth.Identity) {
		require.True(t, id.Known(), "every test in this package authorizes against this identity")

		created, err := sm.AddProfile("owned", &id)
		require.NoError(t, err)

		got, err := sm.ProfileByID(created.ID)
		require.NoError(t, err)
		require.Len(t, got.Owners, 1, "the profile records the identity it was created for")
		assert.True(t, got.Owners[0].Matches(id),
			"the stamped owner %v does not match the identity it was stamped from", got.Owners[0])
	})
}

func TestServiceProfile_ExactID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		created, err := sm.AddProfile("work", nil)
		require.NoError(t, err)

		got := matchOne(t, sm, created.ID.String())
		assert.Equal(t, created.ID, got.ID)
		assert.Equal(t, "work", got.Name)
	})
}

func TestServiceProfile_IDPrefix(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		created, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		prefix := created.ID[:4]
		got := matchOne(t, sm, prefix.String())
		assert.Equal(t, created.ID, got.ID)
	})
}

func TestServiceProfile_AmbiguousPrefix(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		// Plant two profiles whose IDs share a known prefix by writing
		// the files directly, since generated IDs are random.
		user, err := user.Current()
		require.NoError(t, err)
		configDir, err := sm.getConfigDirLegacy(user.Username)
		require.NoError(t, err)
		for _, id := range []string{"abcd1111aaaa", "abcd2222bbbb"} {
			path := filepath.Join(configDir, id+".json")
			require.NoError(t, util.WriteJson(context.Background(), path, &Config{Name: id}))
		}

		// Deciding between the two belongs to whoever knows who is asking, so
		// the matcher hands both back rather than refusing.
		match, err := sm.MatchProfiles("abcd")
		require.NoError(t, err)
		assert.Equal(t, AmbiguityKindIDPrefix, match.Kind)
		assert.Len(t, match.Profiles, 2)
	})
}

func TestServiceProfile_ExactNameUnique(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		_, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		got := matchOne(t, sm, "work")
		assert.Equal(t, "work", got.Name)
	})
}

func TestServiceProfile_AmbiguousName(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		_, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)
		_, err = sm.AddProfile("work", &userID)
		require.NoError(t, err)

		match, err := sm.MatchProfiles("work")
		require.NoError(t, err)
		assert.Equal(t, AmbiguityKindName, match.Kind)
		assert.Len(t, match.Profiles, 2)
	})
}

func TestServiceProfile_NotFound(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		_, err := sm.MatchProfiles("nope")
		assert.ErrorIs(t, err, ErrProfileNotFound)
	})
}

func TestServiceProfile_DefaultByExactID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		got := matchOne(t, sm, defaultProfileName)
		assert.Equal(t, defaultProfileName, got.ID.String())
	})
}

func TestServiceProfile_LegacyFilenameCoexists(t *testing.T) {
	// Legacy profiles stored as <name>.json with no "name" JSON field
	// should still be discoverable by name and removable by name.
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		user, err := user.Current()
		require.NoError(t, err)
		configDir, err := sm.getConfigDirLegacy(user.Username)
		require.NoError(t, err)
		path := filepath.Join(configDir, "legacy.json")
		require.NoError(t, util.WriteJson(context.Background(), path, &Config{}))

		got := matchOne(t, sm, "legacy")
		assert.Equal(t, "legacy", got.ID.String())
		// Name falls back to the filename stem when JSON omits it.
		assert.Equal(t, "legacy", got.Name)
	})
}

func TestAddProfile_AllowsDuplicateWithFlag(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		first, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		second, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)
		assert.NotEqual(t, first.ID, second.ID)
		assert.Equal(t, "work", second.Name)
	})
}

func TestAddProfile_PersistsName(t *testing.T) {
	// The returned Profile carries the name regardless, so this reads the
	// file back: the name has to reach the config apply pass, which is what
	// the owner log line and every later reader see.
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		prof, err := sm.AddProfile("My Work Account", &userID)
		require.NoError(t, err)

		cfg, err := ReadConfig(prof.Path)
		require.NoError(t, err)
		assert.Equal(t, "My Work Account", cfg.Name, "stored config should carry the display name")
		require.Len(t, cfg.Owners, 1, "profile should record its creator as owner")
	})
}

func TestAddProfile_RejectsInvalidNames(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		cases := []string{
			"",                                       // empty
			"\x00\x01",                               // only control chars (becomes empty)
			strings.Repeat("a", maxProfileNameLen+1), // too long
		}
		for _, name := range cases {
			_, err := sm.AddProfile(name, &userID)
			assert.Error(t, err, "expected error for %q", name)
		}
	})
}

func TestRemoveProfile_RejectsInvalidID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		err := sm.RemoveProfile("../escape")
		assert.Error(t, err)
	})
}

func TestSanitizeDisplayName(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"work", "work", false},
		{"My Work Account", "My Work Account", false},
		{"emoji 🚀 ok", "emoji 🚀 ok", false},
		{"漢字テスト", "漢字テスト", false},
		{"with\x00null", "withnull", false},
		{"\x01\x02\x03", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := sanitizeDisplayName(tc.in)
		if tc.wantErr {
			assert.Error(t, err, "case %q", tc.in)
			continue
		}
		assert.NoError(t, err, "case %q", tc.in)
		assert.Equal(t, tc.want, got, "case %q", tc.in)
	}
}

func TestIsValidProfileFilenameStem(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"default", true},
		{"abc123def456", true},
		{"legacy-name", true},
		{"legacy_name", true},
		{"", false},
		{"..", false},
		{"../etc", false},
		{"foo/bar", false},
		{`foo\bar`, false},
		{"with space", false},
		{"with.dot", false},
		{strings.Repeat("a", maxProfileIDLen+1), false},
	}
	for _, tc := range cases {
		got := IsValidProfileFilenameStem(ID(tc.in))
		assert.Equal(t, tc.want, got, "case %q", tc.in)
	}
}

func TestRemoveProfile_DeletesStateFile(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		created, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		user, err := user.Current()
		require.NoError(t, err)
		configDir, err := sm.getConfigDirLegacy(user.Username)
		require.NoError(t, err)
		statePath := filepath.Join(configDir, created.ID.String()+".state.json")
		require.NoError(t, os.WriteFile(statePath, []byte(`{"email":"a@b"}`), 0600))

		require.NoError(t, sm.RemoveProfile(created.ID))
		_, err = os.Stat(statePath)
		assert.True(t, errors.Is(err, os.ErrNotExist), "state file should be removed")
	})
}

// profileIDs is the set of profile IDs in a listing, for membership assertions
// that do not care about the default profile always being present.
func profileIDs(profiles []Profile) []string {
	ids := make([]string, 0, len(profiles))
	for _, p := range profiles {
		ids = append(ids, p.ID.String())
	}
	return ids
}

func TestListProfiles_ScopedToOwner(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, _ ipcauth.Identity) {
		// Two synthetic users rather than the current one: this process is its
		// own daemon, and IsPrivilegedCaller delegates to a caller sharing an
		// unprivileged daemon's identity, so the current user resolves
		// unfiltered here.
		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		bob := ipcauth.KnownForTest(ipcauth.Identity{UID: 4243})
		hers, err := sm.AddProfile("hers", &alice)
		require.NoError(t, err)
		his, err := sm.AddProfile("his", &bob)
		require.NoError(t, err)

		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), hers.ID.String())
		assert.NotContains(t, profileIDs(got), his.ID.String(),
			"another user's profile must not be listed")
	})
}

func TestListProfiles_PrivilegedResolvesUnfiltered(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		other := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		mine, err := sm.AddProfile("mine", &userID)
		require.NoError(t, err)
		theirs, err := sm.AddProfile("theirs", &other)
		require.NoError(t, err)

		root := ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
		got, err := sm.ListProfiles(root)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), mine.ID.String())
		assert.Contains(t, profileIDs(got), theirs.ID.String())
		assert.Contains(t, profileIDs(got), defaultProfileName)
	})
}

func TestListProfiles_UnownedProfilesArePrivilegedOnly(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, _ ipcauth.Identity) {
		// Nobody at the console, so the claim cannot stamp an owner partway
		// through and change what the assertions below are looking at, whatever
		// the machine running the test happens to look like.
		stubConsoleUser(t, false)

		unowned, err := sm.AddProfile("unowned", nil)
		require.NoError(t, err)

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got := claimAndList(t, sm, alice)
		assert.NotContains(t, profileIDs(got), defaultProfileName,
			"the default profile has no exemption, being claimed is what opens it")
		assert.NotContains(t, profileIDs(got), unowned.ID.String(),
			"every profile needs an owner before anyone can address it")

		root := ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
		got = claimAndList(t, sm, root)
		assert.Contains(t, profileIDs(got), defaultProfileName,
			"root still reaches both, which is how an unowned profile gets assigned")
		assert.Contains(t, profileIDs(got), unowned.ID.String())

		nobody, err := sm.ListProfiles(ipcauth.Identity{})
		require.NoError(t, err)
		assert.Empty(t, profileIDs(nobody), "an unattested caller reaches nothing")
	})
}

// withLegacyLayout wires up the globals the way withTestSM does, without the
// identity, since these tests supply their own.
func withLegacyLayout(t *testing.T, fn func(sm *ServiceManager, configDir string)) {
	t.Helper()
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			require.NoError(t, sm.CreateDefaultProfile())
			fn(sm, configDir)
		})
	})
}

// writeLegacyProfile drops a profile into a per-username directory, the layout
// every profile used before the ID-keyed one. It writes no name, since a legacy
// profile took its display name from the filename.
func writeLegacyProfile(t *testing.T, configDir, dirName, id string, fields map[string]any) string {
	t.Helper()
	dir := filepath.Join(configDir, dirName)
	require.NoError(t, os.MkdirAll(dir, 0700))

	doc := map[string]any{}
	for k, v := range fields {
		doc[k] = v
	}
	path := filepath.Join(dir, id+".json")
	require.NoError(t, util.WriteJson(context.Background(), path, doc))
	return path
}

// stubLegacyDir replaces the account lookup, so the claim path can be exercised
// without an account existing on the machine running the test.
func stubLegacyDir(t *testing.T, dir string) {
	t.Helper()
	orig := legacyDirForIdentity
	legacyDirForIdentity = func(ipcauth.Identity) (string, bool) { return dir, dir != "" }
	t.Cleanup(func() { legacyDirForIdentity = orig })
}

func readOwners(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var meta profileMeta
	require.NoError(t, json.Unmarshal(data, &meta))
	return meta.Owners
}

func TestListProfiles_UnownedLegacyProfileIsPrivilegedOnly(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "alice", "work", nil)
		stubLegacyDir(t, "bob")

		bob := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got := claimAndList(t, sm, bob)
		assert.NotContains(t, profileIDs(got), "work",
			"a profile sitting in someone else's directory is not free to take")
		assert.Empty(t, readOwners(t, path), "and it is not claimed on the way past")

		root := ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
		got = claimAndList(t, sm, root)
		assert.Contains(t, profileIDs(got), "work",
			"root still reaches it, which is how it gets reassigned")
	})
}

func TestListProfiles_ClaimsLegacyProfileForItsOwnAccount(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "alice", "work", nil)
		stubLegacyDir(t, "alice")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got := claimAndList(t, sm, alice)
		assert.Contains(t, profileIDs(got), "work",
			"the profile in the caller's own directory is claimed for them and then listed")
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, path))

		// The claim is on disk now, so it is the owner check and not the
		// directory name that keeps the next caller out.
		stubLegacyDir(t, "alice")
		other := ipcauth.KnownForTest(ipcauth.Identity{UID: 5252})
		got = claimAndList(t, sm, other)
		assert.NotContains(t, profileIDs(got), "work")
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, path),
			"a second caller does not overwrite a stamped owner")
	})
}

func TestClaimLegacyProfile_LeavesTheProfileWhereItIs(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "alice", "work", nil)
		for _, suffix := range []string{".state.json", prefsFileSuffix} {
			require.NoError(t, os.WriteFile(filepath.Join(configDir, "alice", "work"+suffix), []byte("{}"), 0600))
		}
		stubLegacyDir(t, "alice")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got := claimAndList(t, sm, alice)

		claimed := ownedProfile(t, got, "uid:4242")
		assert.Equal(t, ID("work"), claimed.ID, "claiming does not re-key the profile")
		assert.Equal(t, path, claimed.Path)
		assert.Equal(t, "alice", claimed.LegacyUserDir,
			"the directory is a leftover now, not something the claim rewrites")

		// The engine captures its state file path at connect time and writes
		// back to whatever it captured, so nothing here may move that file.
		assert.FileExists(t, filepath.Join(configDir, "alice", "work.state.json"))
		assert.FileExists(t, filepath.Join(configDir, "alice", "work"+prefsFileSuffix))
		assert.NoFileExists(t, filepath.Join(configDir, DefaultProfilePathDir, "work.json"))
	})
}

func TestClaimLegacyProfile_NamesakeInAnotherDirectoryIsUntouched(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		writeLegacyProfile(t, configDir, "alice", "work", nil)
		bobs := writeLegacyProfile(t, configDir, "bob", "work", nil)
		stubLegacyDir(t, "alice")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got := claimAndList(t, sm, alice)

		claimed := ownedProfile(t, got, "uid:4242")
		assert.Equal(t, filepath.Join(configDir, "alice", "work.json"), claimed.Path,
			"a legacy ID is a display name two accounts can hold, so the path is what tells them apart")
		assert.Empty(t, readOwners(t, bobs), "bob's namesake is not claimed")
	})
}

func ownedProfile(t *testing.T, profiles []Profile, principal string) Profile {
	t.Helper()
	var found []Profile
	for _, p := range profiles {
		if len(p.Owners) == 1 && p.Owners[0].String() == principal {
			found = append(found, p)
		}
	}
	require.Len(t, found, 1, "exactly one profile is owned by %s", principal)
	return found[0]
}

func TestClaimLegacyProfile_SkipsOneAlreadyOwnedInTheSameDirectory(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		// One unowned profile keeps the claim running over the directory, so
		// the owned one beside it is reached and has to be left alone.
		taken := writeLegacyProfile(t, configDir, "alice", "taken", map[string]any{
			"Owners": []string{"uid:9999"},
		})
		free := writeLegacyProfile(t, configDir, "alice", "free", nil)
		stubLegacyDir(t, "alice")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		claimAndList(t, sm, alice)

		assert.Equal(t, []string{"uid:9999"}, readOwners(t, taken),
			"a profile that already has an owner is not restamped")
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, free))
	})
}

func TestRenameProfile(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		created, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		require.NoError(t, sm.RenameProfile(created.ID, "weekend"))

		got, err := sm.ProfileByID(created.ID)
		require.NoError(t, err)
		assert.Equal(t, "weekend", got.Name, "the new name is on disk")
		assert.Equal(t, created.ID, got.ID, "renaming does not re-key the profile")
		assert.Equal(t, created.Path, got.Path)
	})
}

func TestListProfiles_PrivilegedCallerDoesNotClaim(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "root", "work", nil)
		stubLegacyDir(t, "root")

		root := ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
		got := claimAndList(t, sm, root)
		assert.Contains(t, profileIDs(got), "work")
		assert.Empty(t, readOwners(t, path),
			"root reaches every profile anyway, so the claim must not stamp one")
	})
}

func TestStampOwner(t *testing.T) {
	withLegacyLayout(t, func(_ *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "alice", "work", map[string]any{
			"DisableAutoConnect": true,
		})

		require.NoError(t, StampOwner(path, ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})))
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, path))

		var fields map[string]any
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &fields))
		assert.Equal(t, true, fields["DisableAutoConnect"],
			"the rest of the config survives the stamp")

		require.NoError(t, StampOwner(path, ipcauth.KnownForTest(ipcauth.Identity{UID: 5252})))
		assert.Equal(t, []string{"uid:5252"}, readOwners(t, path),
			"stamping replaces whoever is recorded, the caller decides whether to")
	})
}

func TestClaimLegacyProfile_LeavesAnOwnerItCannotParse(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		// A principal kind this build does not know, which is what a client
		// newer than this one leaves behind after a downgrade. The loader
		// drops such a profile rather than reporting it as unowned, which is
		// what keeps the claim from treating it as free to take.
		path := writeLegacyProfile(t, configDir, "alice", "work", map[string]any{
			"Owners": []string{"group:devs"},
		})
		stubLegacyDir(t, "alice")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got := claimAndList(t, sm, alice)

		assert.NotContains(t, profileIDs(got), "work")
		assert.Equal(t, []string{"group:devs"}, readOwners(t, path),
			"the profile is not taken over, it waits for an explicit claim")
	})
}

func TestResolveLegacyDir_SanitizesTheSameStringTheOldLayoutDid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the windows path resolves a SID rather than a numeric uid")
	}

	u, err := user.Current()
	require.NoError(t, err)
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	require.NoError(t, err)

	got, ok := resolveLegacyDir(ipcauth.KnownForTest(ipcauth.Identity{UID: uint32(uid)}))
	require.True(t, ok)
	assert.Equal(t, sanitizeProfileName(u.Username), got,
		"the directory has to come from the account name, sanitized the way the old layout did")
}

func TestListProfiles_UnreadableOwnersAreSkipped(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, _ ipcauth.Identity) {
		configDir, err := sm.getConfigDir()
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(configDir, 0700))
		// An owner entry that parses as JSON but names no principal: the
		// profile records an owner, so it is not unowned, but nothing can match
		// it.
		const tampered = "abcd1111aaaa"
		path := filepath.Join(configDir, tampered+".json")
		require.NoError(t, os.WriteFile(path, []byte(`{"Name":"tampered","Owners":["garbage"]}`), 0600))

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)
		assert.NotContains(t, profileIDs(got), tampered,
			"a profile whose owners cannot be read must not fall back to unowned")

		// Not even a privileged caller: the loader drops the profile before
		// ownership is ever consulted, so corrupting the owner list hides the
		// profile rather than unlocking it.
		root := ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
		got, err = sm.ListProfiles(root)
		require.NoError(t, err)
		assert.NotContains(t, profileIDs(got), tampered)
	})
}

func TestListProfiles_UnidentifiedCallerGetsNothing(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		_, err := sm.AddProfile("mine", &userID)
		require.NoError(t, err)
		_, err = sm.AddProfile("unowned", nil)
		require.NoError(t, err)

		// The zero Identity carries uid 0, so an unidentified caller must be
		// refused before privilege is ever considered.
		got, err := sm.ListProfiles(ipcauth.Identity{})
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}

func TestActiveProfilePath_RefusesToGuessBetweenNamesakes(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		writeLegacyProfile(t, configDir, "alice", "work", nil)
		writeLegacyProfile(t, configDir, "bob", "work", nil)

		_, err := sm.ActiveProfilePath(&ActiveProfileState{ID: "work"})
		require.ErrorIs(t, err, ErrAmbiguousActiveProfile,
			"running one account's config under another account's name is worse than not running")

		path, err := sm.ActiveProfilePath(&ActiveProfileState{ID: "work", Username: "bob"})
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(configDir, "bob", "work.json"), path,
			"the recorded directory is what tells the namesakes apart")
	})
}

// claimIdentity names a caller the platform could actually hold: a uid names
// nobody on Windows, where a caller is a SID. The account itself need not
// exist, since a claim never looks one up.
func claimIdentity(n uint32) ipcauth.Identity {
	if runtime.GOOS == "windows" {
		return ipcauth.KnownForTest(ipcauth.Identity{SID: fmt.Sprintf("S-1-5-21-1-2-3-%d", n)})
	}
	return ipcauth.KnownForTest(ipcauth.Identity{UID: n})
}

// claimPrincipal is the owner principal that claimIdentity's caller matches.
func claimPrincipal(t *testing.T, n uint32) ipcauth.Principal {
	t.Helper()
	p, err := ipcauth.ValidatePrincipal(ipcauth.OwnerPrincipalForIdentity(claimIdentity(n)))
	require.NoError(t, err)
	return p
}

func TestClaimProfile_RecordsAnArbitraryPrincipal(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, _ ipcauth.Identity) {
		p, err := sm.AddProfile("work", nil)
		require.NoError(t, err)
		require.Empty(t, readOwners(t, p.Path))

		owner := claimPrincipal(t, 4242)
		require.NoError(t, sm.ClaimProfile(p, owner))
		assert.Equal(t, []string{owner.String()}, readOwners(t, p.Path))

		alice := claimIdentity(4242)
		bob := claimIdentity(5252)
		assert.True(t, p.AccessibleBy(alice), "the claim is reflected in memory, not only on disk")
		assert.False(t, p.AccessibleBy(bob))

		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), p.ID.String())

		got, err = sm.ListProfiles(bob)
		require.NoError(t, err)
		assert.NotContains(t, profileIDs(got), p.ID.String())
	})
}

func TestClaimProfile_ReplacesTheRecordedOwner(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, _ ipcauth.Identity) {
		p, err := sm.AddProfile("work", nil)
		require.NoError(t, err)

		require.NoError(t, sm.ClaimProfile(p, claimPrincipal(t, 4242)))
		require.NoError(t, sm.ClaimProfile(p, claimPrincipal(t, 5252)))

		assert.Equal(t, []string{claimPrincipal(t, 5252).String()}, readOwners(t, p.Path),
			"handing a profile over replaces the owner rather than adding one")

		old := claimIdentity(4242)
		assert.False(t, p.AccessibleBy(old), "the previous owner loses access")
	})
}

func TestClaimProfile_ClaimsTheDefaultProfile(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, _ ipcauth.Identity) {
		all, err := sm.loadAllProfiles()
		require.NoError(t, err)
		var def *Profile
		for i := range all {
			if all[i].ID == defaultProfileName {
				def = &all[i]
			}
		}
		require.NotNil(t, def)

		owner := claimPrincipal(t, 4242)
		require.NoError(t, sm.ClaimProfile(def, owner))
		assert.Equal(t, []string{owner.String()}, readOwners(t, DefaultConfigPath),
			"the headless case this exists for: no console user, owner recorded by hand")

		alice := claimIdentity(4242)
		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), defaultProfileName)
	})
}

// ClaimProfile writes the value the ownership check reads back, so an owner no
// caller could ever match is refused here rather than in whichever caller
// happens to reach it.
func TestClaimProfile_RefusesAnOwnerNobodyCanMatch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal ipcauth.Principal
	}{
		{"no kind", ipcauth.Principal{}},
		{"unknown kind", ipcauth.Principal{Kind: "bogus", Value: "1000"}},
		{"uid that is not a number", ipcauth.Principal{Kind: ipcauth.KindUID, Value: "abc"}},
		{"sid that is not a sid", ipcauth.Principal{Kind: ipcauth.KindSID, Value: "any"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTestSM(t, func(sm *ServiceManager, _ ipcauth.Identity) {
				p, err := sm.AddProfile("work", nil)
				require.NoError(t, err)

				require.Error(t, sm.ClaimProfile(p, tc.principal))
				assert.Empty(t, readOwners(t, p.Path), "a refused claim records nothing")
				assert.Empty(t, p.Owners, "and leaves the loaded profile as it was")
			})
		})
	}
}

func TestListProfiles_ClaimKeepsFieldsThisVersionDoesNotModel(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		// What a client newer than this one leaves behind: a key Config has no
		// field for, next to one it does.
		newer := map[string]any{"Enabled": true, "Hosts": []any{"a", "b"}}
		path := writeLegacyProfile(t, configDir, "alice", "work", map[string]any{
			"MTU":            1280,
			"SomethingNewer": newer,
		})
		stubLegacyDir(t, "alice")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		claimAndList(t, sm, alice)
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, path), "the claim still lands")

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(data, &doc))

		assert.Equal(t, newer, doc["SomethingNewer"],
			"a listing must not drop the settings of a client that models more than this one")
		assert.Equal(t, float64(1280), doc["MTU"], "and leaves the ones it does model alone")
		assert.NotContains(t, doc, "PrivateKey",
			"nor write out the rest of Config just because it has fields for it")
	})
}

// stubConsoleUser replaces the console lookup, so the default-profile claim can
// be exercised without the machine running the test having a seat of its own.
func stubConsoleUser(t *testing.T, atConsole bool) {
	t.Helper()
	orig := isConsoleUser
	isConsoleUser = func(ipcauth.Identity) bool { return atConsole }
	t.Cleanup(func() { isConsoleUser = orig })
}

func TestClaimDefaultProfile_ConsoleUserClaimsIt(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, _ string) {
		stubConsoleUser(t, true)

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		claimAndList(t, sm, alice)
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, DefaultConfigPath),
			"the first caller at the console closes the window the default profile is open in")
	})
}

func TestSetProfileField_ReplacesAKeySpelledInAnotherCase(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "alice", "work", map[string]any{
			"owners": []any{"uid:1"},
		})

		require.NoError(t, stampPrincipal(path, "uid:4242"))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(data, &doc))

		assert.NotContains(t, doc, "owners",
			"two spellings of one field would leave the reader to pick")
		assert.Equal(t, []any{"uid:4242"}, doc["Owners"])
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, path))
	})
}

func TestSetProfileField_RefusesADocumentThatIsNotAnObject(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := filepath.Join(configDir, "alice", "work.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
		require.NoError(t, os.WriteFile(path, []byte("null"), 0600))

		require.Error(t, stampPrincipal(path, "uid:4242"),
			"a profile that is not an object is not one an owner can be set on")

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "null", string(data), "and it is left as it was found")
	})
}

func TestSetProfileField_KeepsKeysItWasNotAskedToWrite(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		// Keys Config has no field for, in every shape a newer client could
		// leave one behind.
		unknown := map[string]any{
			"String": "keep me",
			"Number": float64(7),
			"Bool":   true,
			"Null":   nil,
			"List":   []any{"a", float64(2), false},
			"Object": map[string]any{"Nested": map[string]any{"Deep": []any{float64(1)}}},
		}
		fields := map[string]any{"MTU": 1280}
		for k, v := range unknown {
			fields[k] = v
		}
		path := writeLegacyProfile(t, configDir, "alice", "work", fields)

		require.NoError(t, setProfileField(path, ownersFieldName, []string{"uid:4242"}))
		require.NoError(t, setProfileField(path, nameFieldName, "Work"))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(data, &doc))

		for k, want := range unknown {
			assert.Equal(t, want, doc[k],
				"%s is not a key this version models, so it is not this version's to drop", k)
		}
		assert.Equal(t, float64(1280), doc["MTU"], "a key it does model is left where it was too")
		assert.Equal(t, []any{"uid:4242"}, doc["Owners"], "and the fields it was asked for are written")
		assert.Equal(t, "Work", doc["Name"])
		assert.Len(t, doc, len(unknown)+3, "with nothing else added")
	})
}

func TestClaimDefaultProfile_CallerAwayFromTheConsoleDoesNotClaimIt(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, _ string) {
		stubConsoleUser(t, false)

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		claimAndList(t, sm, alice)
		assert.Empty(t, readOwners(t, DefaultConfigPath),
			"a local caller who is not at the console must not take the machine's profile")
	})
}

func TestClaimDefaultProfile_DisableEnvWithholdsTheClaim(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, _ string) {
		stubConsoleUser(t, true)
		t.Setenv(EnvDisableDefaultProfileClaim, "true")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		claimAndList(t, sm, alice)
		assert.Empty(t, readOwners(t, DefaultConfigPath),
			"the flag withholds the claim even from a caller who would otherwise get it")
	})
}

func TestClaimDefaultProfile_UnparseableDisableEnvLeavesTheClaimOn(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, _ string) {
		stubConsoleUser(t, true)
		t.Setenv(EnvDisableDefaultProfileClaim, "yes please")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		claimAndList(t, sm, alice)
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, DefaultConfigPath),
			"a typo must not be what turns a safety mechanism off")
	})
}

// The default profile's file is named by the platform, not after its ID: the
// mobile bindings call it netbird.cfg. Deriving the ID from the filename drops
// the profile out of every listing there, and the name has no ".json" to trim
// so the stem is rejected outright.
func TestLoadAllProfiles_DefaultProfileIsNotNamedAfterItsFile(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			original := DefaultConfigPath
			DefaultConfigPath = filepath.Join(configDir, "netbird.cfg")
			t.Cleanup(func() { DefaultConfigPath = original })

			sm := &ServiceManager{}
			require.NoError(t, sm.CreateDefaultProfile())

			profiles, err := sm.loadAllProfiles()
			require.NoError(t, err)
			assert.Contains(t, profileIDs(profiles), defaultProfileName,
				"the default profile is missing from the listing on a platform that names its file")

			got, err := sm.ProfileByID(defaultProfileName)
			require.NoError(t, err)
			assert.Equal(t, DefaultConfigPath, got.Path)

			byPath, err := sm.ProfileByPath(DefaultConfigPath)
			require.NoError(t, err)
			assert.Equal(t, ID(defaultProfileName), byPath.ID)
		})
	})
}
