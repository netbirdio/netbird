//go:build !windows && !wasm

package ipcauth

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A symlink is the shape the arbitrary-read attempt takes: the caller owns the
// link, the file it points at belongs to someone else.
func TestOpenOwnedFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	require.NoError(t, os.WriteFile(target, []byte("secret"), 0600))

	link := filepath.Join(dir, "gui-client.log")
	require.NoError(t, os.Symlink(target, link))

	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	_, err = OpenOwnedFile(id, link)
	// O_NOFOLLOW on a symlink reports ELOOP on Linux/Darwin and EMLINK on FreeBSD.
	if !errors.Is(err, syscall.ELOOP) && !errors.Is(err, syscall.EMLINK) {
		t.Fatalf("symlink open: got %v, want ELOOP or EMLINK", err)
	}
}

// A fifo would block the open until a writer showed up, stalling the daemon
// while it holds its lock.
func TestOpenOwnedFileRefusesFifoWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gui-client.log")
	require.NoError(t, syscall.Mkfifo(path, 0600))

	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := OpenOwnedFile(id, path)
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorContains(t, err, "not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("opening a fifo blocked")
	}
}
