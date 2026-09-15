package profilemanager

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/util"
)

// withTestSM wires up patched globals + a clean config dir and returns a
// fully initialized ServiceManager plus the username we are scoped to.
func withTestSM(t *testing.T, fn func(sm *ServiceManager, username string)) {
	t.Helper()
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			u, err := user.Current()
			require.NoError(t, err)
			sm := &ServiceManager{}
			require.NoError(t, sm.CreateDefaultProfile())
			fn(sm, u.Username)
		})
	})
}

func TestServiceProfile_ExactID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		got, err := sm.ResolveProfile(created.ID.String(), username)
		require.NoError(t, err)
		assert.Equal(t, created.ID, got.ID)
		assert.Equal(t, "work", got.Name)
	})
}

func TestServiceProfile_IDPrefix(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		prefix := created.ID[:4]
		got, err := sm.ResolveProfile(prefix.String(), username)
		require.NoError(t, err)
		assert.Equal(t, created.ID, got.ID)
	})
}

func TestServiceProfile_AmbiguousPrefix(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		// Plant two profiles whose IDs share a known prefix by writing
		// the files directly, since generated IDs are random.
		configDir, err := sm.getConfigDir(username)
		require.NoError(t, err)
		for _, id := range []string{"abcd1111aaaa", "abcd2222bbbb"} {
			path := filepath.Join(configDir, id+".json")
			require.NoError(t, util.WriteJson(context.Background(), path, &Config{Name: id}))
		}

		_, err = sm.ResolveProfile("abcd", username)
		var amb *ErrAmbiguousHandle
		require.ErrorAs(t, err, &amb)
		assert.Equal(t, AmbiguityKindIDPrefix, amb.Kind)
		assert.Len(t, amb.Candidates, 2)
	})
}

func TestServiceProfile_ExactNameUnique(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		_, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		got, err := sm.ResolveProfile("work", username)
		require.NoError(t, err)
		assert.Equal(t, "work", got.Name)
	})
}

func TestServiceProfile_AmbiguousName(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		_, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)
		_, err = sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		_, err = sm.ResolveProfile("work", username)
		var amb *ErrAmbiguousHandle
		require.ErrorAs(t, err, &amb)
		assert.Equal(t, AmbiguityKindName, amb.Kind)
		assert.Len(t, amb.Candidates, 2)
	})
}

func TestServiceProfile_NotFound(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		_, err := sm.ResolveProfile("nope", username)
		assert.ErrorIs(t, err, ErrProfileNotFound)
	})
}

func TestServiceProfile_DefaultByExactID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		got, err := sm.ResolveProfile(defaultProfileName, username)
		require.NoError(t, err)
		assert.Equal(t, defaultProfileName, got.ID.String())
	})
}

func TestServiceProfile_LegacyFilenameCoexists(t *testing.T) {
	// Legacy profiles stored as <name>.json with no "name" JSON field
	// should still be discoverable by name and removable by name.
	withTestSM(t, func(sm *ServiceManager, username string) {
		configDir, err := sm.getConfigDir(username)
		require.NoError(t, err)
		path := filepath.Join(configDir, "legacy.json")
		require.NoError(t, util.WriteJson(context.Background(), path, &Config{}))

		got, err := sm.ResolveProfile("legacy", username)
		require.NoError(t, err)
		assert.Equal(t, "legacy", got.ID.String())
		// Name falls back to the filename stem when JSON omits it.
		assert.Equal(t, "legacy", got.Name)
	})
}

func TestAddProfile_AllowsDuplicateWithFlag(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		first, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		second, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)
		assert.NotEqual(t, first.ID, second.ID)
		assert.Equal(t, "work", second.Name)
	})
}

func TestAddProfile_RejectsInvalidNames(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		cases := []string{
			"",                                       // empty
			"\x00\x01",                               // only control chars (becomes empty)
			strings.Repeat("a", maxProfileNameLen+1), // too long
		}
		for _, name := range cases {
			_, err := sm.AddProfile(name, username, nil)
			assert.Error(t, err, "expected error for %q", name)
		}
	})
}

func TestRemoveProfile_RejectsInvalidID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		err := sm.RemoveProfile("../escape", username)
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
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		configDir, err := sm.getConfigDir(username)
		require.NoError(t, err)
		statePath := filepath.Join(configDir, created.ID.String()+".state.json")
		require.NoError(t, os.WriteFile(statePath, []byte(`{"email":"a@b"}`), 0600))

		require.NoError(t, sm.RemoveProfile(created.ID, username))
		_, err = os.Stat(statePath)
		assert.True(t, errors.Is(err, os.ErrNotExist), "state file should be removed")
	})
}
