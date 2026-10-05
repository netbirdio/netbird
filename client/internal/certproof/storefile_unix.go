//go:build unix

package certproof

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// readStoreFile reads a certificate or key file of the PEM directory as the daemon may
// trust it: the path must not be a symlink and must be a regular file that only root or
// this process's own user can write. Otherwise a user able to place or redirect a file
// could make the daemon sign with a key of their choosing, or with a root-only key kept
// elsewhere on the machine. The file is checked through the descriptor it is read from,
// so it cannot be swapped between the check and the read.
func readStoreFile(path string) ([]byte, error) {
	// O_NONBLOCK keeps a FIFO planted in the directory from blocking the open; the
	// regular-file check below then refuses it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := checkTrustedOwner(info); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if info.Size() > maxStoreFileSize {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit", path, info.Size(), maxStoreFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStoreFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxStoreFileSize {
		return nil, fmt.Errorf("%s grew past the %d byte limit while being read", path, maxStoreFileSize)
	}
	return data, nil
}

// checkStoreDir refuses a PEM directory that someone other than root or this process's
// user could add files to or rename files in.
func checkStoreDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := checkTrustedOwner(info); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	return nil
}

// checkTrustedOwner requires info to belong to root or to this process's user, and to be
// writable by nobody else: not by others, and by its group only when that is root's group.
// An owner that cannot be read is refused.
func checkTrustedOwner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("owner cannot be determined")
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, not by root", st.Uid)
	}
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return fmt.Errorf("writable by any user (mode %#o)", perm)
	}
	if perm&0o020 != 0 && st.Gid != 0 {
		return fmt.Errorf("writable by group %d (mode %#o)", st.Gid, perm)
	}
	return nil
}
