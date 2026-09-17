package ipcauth

import (
	"fmt"
	"os"
)

// OpenOwnedFile opens path for reading on behalf of the IPC caller identified by
// id, and fails unless the opened file is a regular file that id owns.
//
// It exists for the paths a local caller hands to the daemon over the IPC. The
// daemon runs as root, so opening such a path unchecked lets any local user read
// any file through it. Ownership is the invariant that keeps the daemon from
// reading, with its own privileges, a file the caller could not read itself: a
// symlink or hard link planted at the path resolves to a file someone else owns
// and is refused.
//
// The check is made against the open descriptor rather than the path, so
// swapping the path between the check and the read cannot change the answer.
//
// A privileged caller is exempt: it can read the file directly, so refusing it
// here would protect nothing. The regular-file requirement still applies to
// everyone, since a fifo or device planted at the path is never a log file.
func OpenOwnedFile(id Identity, path string) (*os.File, error) {
	f, err := openForRead(path)
	if err != nil {
		return nil, err
	}

	if err := checkOwnership(id, f); err != nil {
		if cerr := f.Close(); cerr != nil {
			return nil, fmt.Errorf("%w (close: %v)", err, cerr)
		}
		return nil, err
	}

	return f, nil
}

func checkOwnership(id Identity, f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", f.Name(), err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", f.Name())
	}

	if IsPrivilegedCaller(id) {
		return nil
	}

	owned, err := fileOwnedBy(id, f)
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", f.Name(), err)
	}
	if !owned {
		return fmt.Errorf("%s is not owned by the caller (%s)", f.Name(), id)
	}

	return nil
}
