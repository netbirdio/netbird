package util

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// openRead opens path for reading without holding it against a rename.
//
// os.Open asks for FILE_SHARE_READ|FILE_SHARE_WRITE and leaves out delete
// sharing, so while the handle lives nothing can rename over the file. Every
// config here is rewritten as a temp file renamed into place, so a read and a
// write of the same file collide and the write is the one that fails, with
// "Access is denied". os.Root opens through NtCreateFile with delete sharing,
// which is the behaviour Unix has always had.
//
// Root is directory scoped, so the file is opened by name under a root on its
// own directory. That constrains the last component only: the directory path
// itself resolves normally, symlinks below it are followed as long as they stay
// inside and are relative, and traversing a mount or a bind mount is not
// restricted at all.
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
// os.Rename is MoveFileEx, which has to free the destination's directory entry
// there and then; a file with live handles can only be marked delete-pending,
// so the replace is refused however the readers shared it. os.Root.Rename asks
// for POSIX semantics, which unlink the destination immediately and leave open
// handles reading the version they opened, and falls back to the classic form
// on a filesystem or a Windows build that will not take it.
//
// A rename across directories is outside what one root covers, and every caller
// here writes a temp file beside its destination, so that case keeps MoveFileEx.
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
// file by the base name it was opened with. The cause is carried over so
// errors.Is(err, os.ErrNotExist) keeps answering for callers that seed a file
// they find missing.
func pathError(op, path string, err error) error {
	var perr *fs.PathError
	if errors.As(err, &perr) {
		err = perr.Err
	}
	return &fs.PathError{Op: op, Path: path, Err: err}
}

// linkError does the same for a rename, which reports both files by their base
// names.
func linkError(op, oldpath, newpath string, err error) error {
	var lerr *os.LinkError
	if errors.As(err, &lerr) {
		err = lerr.Err
	}
	return &os.LinkError{Op: op, Old: oldpath, New: newpath, Err: err}
}
