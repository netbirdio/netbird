//go:build !windows

package util

import "os"

// openRead opens path for reading. Only Windows needs more than this: there a
// plain open holds the file against the rename that replaces it.
func openRead(path string) (*os.File, error) {
	return os.Open(path)
}

// renameFile replaces newpath with oldpath.
func renameFile(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}
