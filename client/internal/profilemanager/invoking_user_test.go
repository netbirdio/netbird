package profilemanager

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvokingUserFallsBackToProcessUser(t *testing.T) {
	t.Setenv("SUDO_USER", "")

	got, err := InvokingUser()
	require.NoError(t, err)

	current, err := user.Current()
	require.NoError(t, err)
	assert.Equal(t, current.Username, got.Username)
}

func TestSudoInvokingUserInactiveWithoutSudoContext(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	_, ok := sudoInvokingUser()
	assert.False(t, ok)
}

func TestSudoInvokingUserIgnoresRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to enter the sudo branch")
	}
	t.Setenv("SUDO_USER", "root")
	_, ok := sudoInvokingUser()
	assert.False(t, ok, "sudo from a root shell must not redirect anything")
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
	t.Setenv("SUDO_USER", "")
	assert.Equal(t, os.Geteuid() == 0, IsPlainRoot())
}
