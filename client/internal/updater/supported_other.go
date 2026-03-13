//go:build !windows && !darwin

package updater

func isAutoUpdateSupported() bool {
	return false
}
