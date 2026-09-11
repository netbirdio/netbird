package profilemanager

import (
	"context"
	"encoding/json"
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

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/util"
)

// withTestSM wires up patched globals + a clean config dir and returns a
// fully initialized ServiceManager plus the username we are scoped to.
func withTestSM(t *testing.T, fn func(sm *ServiceManager, id ipcauth.Identity)) {
	t.Helper()
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			u, err := user.Current()
			require.NoError(t, err)
			sm := &ServiceManager{}
			require.NoError(t, sm.CreateDefaultProfile())
			uid, err := strconv.ParseUint(u.Uid, 10, 32)
			require.NoError(t, err)
			userID := ipcauth.Identity{UID: uint32(uid)}
			userID = ipcauth.KnownForTest(userID)
			fn(sm, userID)
		})
	})
}

func TestServiceProfile_ExactID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		created, err := sm.AddProfile("work", nil)
		require.NoError(t, err)

		got, err := sm.ResolveProfile(created.ID.String(), userID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, got.ID)
		assert.Equal(t, "work", got.Name)
	})
}

func TestServiceProfile_IDPrefix(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		created, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		prefix := created.ID[:4]
		got, err := sm.ResolveProfile(prefix.String(), userID)
		require.NoError(t, err)
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

		_, err = sm.ResolveProfile("abcd", userID)
		var amb *ErrAmbiguousHandle
		require.ErrorAs(t, err, &amb)
		assert.Equal(t, AmbiguityKindIDPrefix, amb.Kind)
		assert.Len(t, amb.Candidates, 2)
	})
}

func TestServiceProfile_ExactNameUnique(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		_, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		got, err := sm.ResolveProfile("work", userID)
		require.NoError(t, err)
		assert.Equal(t, "work", got.Name)
	})
}

func TestServiceProfile_AmbiguousName(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		_, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)
		_, err = sm.AddProfile("work", &userID)
		require.NoError(t, err)

		_, err = sm.ResolveProfile("work", userID)
		var amb *ErrAmbiguousHandle
		require.ErrorAs(t, err, &amb)
		assert.Equal(t, AmbiguityKindName, amb.Kind)
		assert.Len(t, amb.Candidates, 2)
	})
}

func TestServiceProfile_NotFound(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		_, err := sm.ResolveProfile("nope", userID)
		assert.ErrorIs(t, err, ErrProfileNotFound)
	})
}

func TestServiceProfile_DefaultByExactID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		got, err := sm.ResolveProfile(defaultProfileName, userID)
		require.NoError(t, err)
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

		got, err := sm.ResolveProfile("legacy", userID)
		require.NoError(t, err)
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
		err := sm.RemoveProfile("../escape", userID)
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

		require.NoError(t, sm.RemoveProfile(created.ID, userID))
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

func TestListProfiles_UnownedOutsideALegacyDirIsOpen(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, _ ipcauth.Identity) {
		unowned, err := sm.AddProfile("unowned", nil)
		require.NoError(t, err)

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), unowned.ID.String(),
			"a profile that never had an owner stays usable until someone claims it")
		assert.Contains(t, profileIDs(got), defaultProfileName,
			"a fresh install has to be usable before anything is claimed")

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
	var meta ownerMeta
	require.NoError(t, json.Unmarshal(data, &meta))
	return meta.Owners
}

func TestListProfiles_UnownedLegacyProfileIsPrivilegedOnly(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "alice", "work", nil)
		stubLegacyDir(t, "bob")

		bob := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got, err := sm.ListProfiles(bob)
		require.NoError(t, err)
		assert.NotContains(t, profileIDs(got), "work",
			"a profile sitting in someone else's directory is not free to take")
		assert.Empty(t, readOwners(t, path), "and it is not claimed on the way past")

		root := ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
		got, err = sm.ListProfiles(root)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), "work",
			"root still reaches it, which is how it gets reassigned")
	})
}

func TestListProfiles_ClaimsLegacyProfileForItsOwnAccount(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "alice", "work", nil)
		stubLegacyDir(t, "alice")

		alice := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), "work",
			"the claim lands before the listing is filtered, so the gap closes in one call")
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, path))

		// The claim is on disk now, so it is the owner check and not the
		// directory name that keeps the next caller out.
		stubLegacyDir(t, "alice")
		other := ipcauth.KnownForTest(ipcauth.Identity{UID: 5252})
		got, err = sm.ListProfiles(other)
		require.NoError(t, err)
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
		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)

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
		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)

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
		_, err := sm.ListProfiles(alice)
		require.NoError(t, err)

		assert.Equal(t, []string{"uid:9999"}, readOwners(t, taken),
			"a profile that already has an owner is not restamped")
		assert.Equal(t, []string{"uid:4242"}, readOwners(t, free))
	})
}

func TestRenameProfile(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		created, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		require.NoError(t, sm.RenameProfile(created.ID, userID, "weekend"))

		got, err := sm.ResolveProfile(created.ID.String(), userID)
		require.NoError(t, err)
		assert.Equal(t, "weekend", got.Name, "the new name is on disk")
		assert.Equal(t, created.ID, got.ID, "renaming does not re-key the profile")
		assert.Equal(t, created.Path, got.Path)
	})
}

func TestRenameProfile_NotTheCallersProfile(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		created, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		stranger := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		require.Error(t, sm.RenameProfile(created.ID, stranger, "weekend"),
			"a profile the caller cannot address is not theirs to rename")

		got, err := sm.ResolveProfile(created.ID.String(), userID)
		require.NoError(t, err)
		assert.Equal(t, "work", got.Name)
	})
}

func TestListProfiles_PrivilegedCallerDoesNotClaim(t *testing.T) {
	withLegacyLayout(t, func(sm *ServiceManager, configDir string) {
		path := writeLegacyProfile(t, configDir, "root", "work", nil)
		stubLegacyDir(t, "root")

		root := ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
		got, err := sm.ListProfiles(root)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), "work")
		assert.Empty(t, readOwners(t, path),
			"root reaches every profile anyway, so a listing must not stamp one")
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
		got, err := sm.ListProfiles(alice)
		require.NoError(t, err)

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
