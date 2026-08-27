package profilemanager

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvokingUserFallsBackToProcessUser(t *testing.T) {
	t.Setenv(envSudoUser, "")

	got, err := InvokingUser()
	require.NoError(t, err)

	current, err := user.Current()
	require.NoError(t, err)
	assert.Equal(t, current.Username, got.Username)
}

func TestSudoInvokingUserInactiveWithoutSudoContext(t *testing.T) {
	t.Setenv(envSudoUser, "")
	_, ok := sudoInvokingUser()
	assert.False(t, ok)
}

func TestSudoInvokingUserIgnoresRoot(t *testing.T) {
	t.Setenv(envSudoUser, "root")
	origEuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = origEuid })

	_, ok := sudoInvokingUser()
	assert.False(t, ok, "sudo from a root shell must not redirect anything")
	assert.False(t, sudoActive())
	assert.True(t, IsPlainRoot())
}

func TestSudoInvokingUserResolvesInvokingUser(t *testing.T) {
	fakeSudo(t, filepath.Join("/home", "misha"))

	u, ok := sudoInvokingUser()
	require.True(t, ok)
	assert.Equal(t, "misha", u.Username)

	got, err := InvokingUser()
	require.NoError(t, err)
	assert.Equal(t, "misha", got.Username)

	assert.False(t, IsPlainRoot())
}

func TestInvokingUserFailsClosedWhenSudoLookupFails(t *testing.T) {
	fakeSudo(t, filepath.Join("/home", "misha"))
	lookupUser = func(string) (*user.User, error) { return nil, errors.New("nss unavailable") }

	got, err := InvokingUser()
	require.Error(t, err)
	assert.Nil(t, got, "must not resolve to the root process user")
}

func TestProfileFilePathFailsClosedWhenSudoLookupFails(t *testing.T) {
	profilesRoot := t.TempDir()
	fakeSudo(t, filepath.Join("/home", "misha"))
	lookupUser = func(string) (*user.User, error) { return nil, errors.New("nss unavailable") }

	origDir := DefaultConfigPathDir
	DefaultConfigPathDir = profilesRoot
	t.Cleanup(func() { DefaultConfigPathDir = origDir })

	p := &Profile{ID: "0123456789abcdef0123456789abcdef"}
	_, err := p.FilePath()
	require.Error(t, err)
	assertNoEntries(t, profilesRoot)
}

func TestSudoActiveSurvivesLookupFailure(t *testing.T) {
	fakeSudo(t, filepath.Join("/home", "misha"))
	lookupUser = func(string) (*user.User, error) { return nil, errors.New("nss unavailable") }

	_, ok := sudoInvokingUser()
	assert.False(t, ok)
	assert.True(t, sudoActive())
	assert.True(t, IsPlainRoot())
}

func TestGetConfigDirUnderSudoIsReadOnly(t *testing.T) {
	home := t.TempDir()
	fakeSudo(t, home)

	base, err := baseConfigDir()
	require.NoError(t, err)
	if runtime.GOOS == "darwin" {
		assert.Equal(t, filepath.Join(home, "Library", "Application Support"), base)
	} else {
		assert.Equal(t, filepath.Join(home, ".config"), base)
	}

	dir, err := getConfigDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "netbird"), dir)
	assert.NoDirExists(t, dir)
}

func TestBaseConfigDirFailsClosedWhenSudoLookupFails(t *testing.T) {
	fakeSudo(t, filepath.Join("/home", "misha"))
	lookupUser = func(string) (*user.User, error) { return nil, errors.New("nss unavailable") }

	_, err := baseConfigDir()
	require.Error(t, err)

	_, err = getConfigDir()
	require.Error(t, err)
}

func TestSwitchProfileSkipsStateWriteUnderSudo(t *testing.T) {
	home := t.TempDir()
	fakeSudo(t, home)

	pm := NewProfileManager()
	require.NoError(t, pm.SwitchProfile(defaultProfileName))
	assertNoEntries(t, home)
}

func TestSetProfileStateSkipsWriteUnderSudo(t *testing.T) {
	home := t.TempDir()
	fakeSudo(t, home)

	pm := NewProfileManager()
	require.NoError(t, pm.SetProfileState(defaultProfileName, &ProfileState{Email: "misha@example.com"}))
	assertNoEntries(t, home)
}

func TestRemoveProfileStateSkipsRemoveUnderSudo(t *testing.T) {
	home := t.TempDir()
	stateDir := filepath.Join(home, ".config", "netbird")
	if runtime.GOOS == "darwin" {
		stateDir = filepath.Join(home, "Library", "Application Support", "netbird")
	}
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	stateFile := filepath.Join(stateDir, "default.state.json")
	require.NoError(t, os.WriteFile(stateFile, []byte(`{"email":"misha@example.com"}`), 0o600))

	fakeSudo(t, home)
	pm := NewProfileManager()
	require.NoError(t, pm.RemoveProfileState("default"))
	assert.FileExists(t, stateFile)
}

func TestUserBaseConfigDir(t *testing.T) {
	u := &user.User{Username: "misha", HomeDir: filepath.Join("/home", "misha")}
	dir, err := userBaseConfigDir(u)
	require.NoError(t, err)
	if runtime.GOOS == "darwin" {
		assert.Equal(t, filepath.Join(u.HomeDir, "Library", "Application Support"), dir)
	} else {
		assert.Equal(t, filepath.Join(u.HomeDir, ".config"), dir)
	}

	_, err = userBaseConfigDir(&user.User{Username: "nohome"})
	require.Error(t, err)
}

func TestIsPlainRoot(t *testing.T) {
	t.Setenv(envSudoUser, "")
	origEuid := geteuid
	t.Cleanup(func() { geteuid = origEuid })

	geteuid = func() int { return 1000 }
	assert.False(t, IsPlainRoot())

	geteuid = func() int { return 0 }
	assert.True(t, IsPlainRoot())
}

func TestMirrorIsAuthoritative(t *testing.T) {
	t.Setenv(envSudoUser, "")
	origEuid := geteuid
	t.Cleanup(func() { geteuid = origEuid })

	geteuid = func() int { return 1000 }
	assert.True(t, MirrorIsAuthoritative(), "a normal user's own mirror is authoritative")

	geteuid = func() int { return 0 }
	assert.False(t, MirrorIsAuthoritative(), "plain root has no authoritative mirror")
}

func TestMirrorIsAuthoritativeFalseUnderSudo(t *testing.T) {
	fakeSudo(t, filepath.Join("/home", "misha"))
	assert.False(t, MirrorIsAuthoritative(), "the sudo mirror is frozen, so it is not authoritative")
}

func fakeSudo(t *testing.T, home string) {
	t.Helper()
	t.Setenv(envSudoUser, "misha")

	origEuid := geteuid
	origLookup := lookupUser
	origOverride := ConfigDirOverride
	geteuid = func() int { return 0 }
	lookupUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "1234", Gid: "1234", HomeDir: home}, nil
	}
	ConfigDirOverride = ""
	t.Cleanup(func() {
		geteuid = origEuid
		lookupUser = origLookup
		ConfigDirOverride = origOverride
	})
}

func assertNoEntries(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			t.Errorf("unexpected entry created under %s: %s", root, path)
		}
		return nil
	})
	require.NoError(t, err)
}
