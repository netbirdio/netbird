//go:build !windows

package util

func EnforcePermission(dirPath string) error {
	return nil
}
