//go:build !windows && !wasm

package ipcauth

import (
	"fmt"
	"os"
	"syscall"
)

// openForRead opens a caller-supplied path without following a symlink at its
// final component and without blocking: a fifo planted at the path would
// otherwise stall the open until a writer appears, and the daemon holds a lock
// while it collects the file.
func openForRead(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}

func fileOwnedBy(id Identity, f *os.File) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("no owner information in %T", info.Sys())
	}

	return stat.Uid == id.UID, nil
}
