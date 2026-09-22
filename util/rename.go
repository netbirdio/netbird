//go:build !windows

package util

import "os"

// renameFile replaces newpath with oldpath.
func renameFile(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}
