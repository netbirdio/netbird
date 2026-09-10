package profilemanager

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
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

func TestListProfiles_UnownedStaysOpenUntilClaimed(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		unowned, err := sm.AddProfile("unowned", nil)
		require.NoError(t, err)

		other := ipcauth.KnownForTest(ipcauth.Identity{UID: 4242})
		got, err := sm.ListProfiles(other)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), unowned.ID.String(),
			"an unowned profile is addressable until it is claimed")
	})
}

func TestListProfiles_UnreadableOwnersArePrivilegedOnly(t *testing.T) {
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

		root := ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
		got, err = sm.ListProfiles(root)
		require.NoError(t, err)
		assert.Contains(t, profileIDs(got), tampered)
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
