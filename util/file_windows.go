package util

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// openRead opens path for reading without holding it against a rename.
//
// os.Open does not set FILE_SHARE_DELETE on Windows, so you cannot rename an
// open file like on UNIX. This caused concurrency issues with active state
// config file.
//
// os.Root opens through NtCreateFile with delete sharing, which is the
// behaviour Unix has.
// https://cs.opensource.google/go/go/+/refs/tags/go1.27.1:src/os/root_windows.go;drc=a4f5d9bbdbdf42da7e2d7e976ac85753c4db5d75;l=176
func openRead(path string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		// Names the file the caller asked for, not the directory the root
		// failed on, so a missing directory reads like a missing file.
		return nil, pathError("open", path, err)
	}
	defer func() { _ = root.Close() }()

	// The file outlives the root: closing a Root closes the directory handle it
	// holds, not the files opened through it.
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, pathError("open", path, err)
	}
	return f, nil
}

// renameFile replaces newpath with oldpath, including while something holds
// newpath open for reading.
//
// os.Root.Rename asks for POSIX semantics, which unlink the destination
// immediately and leave open handles reading the version they opened.
// https://cs.opensource.google/go/go/+/master:src/internal/syscall/windows/at_windows.go;drc=a4f5d9bbdbdf42da7e2d7e976ac85753c4db5d75;l=384
func renameFile(oldpath, newpath string) error {
	dir := filepath.Dir(newpath)
	if filepath.Dir(oldpath) != dir {
		return os.Rename(oldpath, newpath)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return os.Rename(oldpath, newpath)
	}
	defer func() { _ = root.Close() }()

	if err := root.Rename(filepath.Base(oldpath), filepath.Base(newpath)); err != nil {
		return linkError("rename", oldpath, newpath, err)
	}
	return nil
}

// pathError restores the full path on an error from a root, which names the
// file by the base name it was opened with.
func pathError(op, path string, err error) error {
	var perr *fs.PathError
	if errors.As(err, &perr) {
		err = perr.Err
	}
	return &fs.PathError{Op: op, Path: path, Err: err}
}

// linkError does the same as pathError for a rename, which reports both files
// by their base names.
func linkError(op, oldpath, newpath string, err error) error {
	var lerr *os.LinkError
	if errors.As(err, &lerr) {
		err = lerr.Err
	}
	return &os.LinkError{Op: op, Old: oldpath, New: newpath, Err: err}
}
