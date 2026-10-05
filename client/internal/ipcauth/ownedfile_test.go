package ipcauth

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// otherIdentity is an unprivileged caller that owns nothing the test creates.
func otherIdentity(t *testing.T) Identity {
	t.Helper()
	if runtime.GOOS == "windows" {
		return Identity{SID: "S-1-5-21-1-2-3-1001"}
	}
	return Identity{UID: uint32(os.Geteuid() + 1), GID: uint32(os.Getegid() + 1)}
}

func TestOpenOwnedFileReadsFileOwnedByCaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gui-client.log")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0600))

	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	f, err := OpenOwnedFile(id, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	content, err := io.ReadAll(f)
	require.NoError(t, err)
	require.Equal(t, "hello", string(content))
}

func TestOpenOwnedFileRefusesFileOwnedByAnother(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gui-client.log")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0600))

	_, err := OpenOwnedFile(otherIdentity(t), path)
	require.ErrorContains(t, err, "not owned by the caller")
}

func TestOpenOwnedFileRefusesNonRegularFile(t *testing.T) {
	dir := t.TempDir()

	// The caller owns the directory, so this is the regular-file requirement
	// talking, not the ownership check.
	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	_, err = OpenOwnedFile(id, dir)
	require.ErrorContains(t, err, "not a regular file")
}

func TestOpenOwnedFileRefusesMissingFile(t *testing.T) {
	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	_, err = OpenOwnedFile(id, filepath.Join(t.TempDir(), "absent.log"))
	require.Error(t, err)
}
