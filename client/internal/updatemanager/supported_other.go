//go:build !windows && !darwin

package updatemanager

func isAutoUpdateSupported() bool {
	return false
}
