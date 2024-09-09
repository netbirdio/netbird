//go:build !windows

package util

func enforcePermission(dirPath string) error {
	return nil
}
