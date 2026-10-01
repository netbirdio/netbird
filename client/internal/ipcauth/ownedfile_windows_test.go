//go:build windows

package ipcauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// fileOwnerSID reads the owner SID of path the same way OpenOwnedFile does, so
// the test can construct an Identity that matches (or deliberately does not).
func fileOwnerSID(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	return owner.String()
}

// The allow branch of fileOwnedBy is the SID-equality path the legitimate GUI
// flow depends on. Running elevated, a created file is owned by
// BUILTIN\Administrators; an Identity carrying that SID with Elevated=false and
// no groups is unprivileged by IsPrivileged (which reads the token, not the
// SID's RID), so this exercises the real GetSecurityInfo equality rather than
// the privileged-caller shortcut.
func TestOpenOwnedFileWindowsOwnerMatchAllows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gui-client.log")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0600))

	ownerSID := fileOwnerSID(t, path)
	id := Identity{SID: ownerSID}
	require.False(t, id.IsPrivileged(), "identity built from the owner SID must be unprivileged for this to test the match path")

	f, err := OpenOwnedFile(id, path)
	require.NoError(t, err)
	_ = f.Close()
}

func TestOpenOwnedFileWindowsOwnerMismatchRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gui-client.log")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0600))

	other := Identity{SID: "S-1-5-21-9-9-9-9999"}
	require.False(t, other.IsPrivileged())

	_, err := OpenOwnedFile(other, path)
	require.ErrorContains(t, err, "not owned by the caller")
}

// FILE_FLAG_OPEN_REPARSE_POINT must make OpenOwnedFile refuse a symlink the same
// way O_NOFOLLOW does on Unix, so a planted link can't redirect the read to
// another file. Creating a symlink needs a privilege the runner may lack, so the
// test skips rather than fails when it can't.
func TestOpenOwnedFileWindowsRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	require.NoError(t, os.WriteFile(target, []byte("secret"), 0600))

	link := filepath.Join(dir, "gui-client.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink (privilege not held?): %v", err)
	}

	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	_, err = OpenOwnedFile(id, link)
	require.Error(t, err, "a symlink must be refused")
}
