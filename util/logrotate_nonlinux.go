//go:build !linux

package util

// FindLogrotateConflicts scans the standard logrotate locations and returns
// true and the first config file that contains a non-comment line indicating
// it's configured for netbird.
// Will always return false for non-linux device.
func FindFirstLogrotateConflict() (bool, string) {
	return false, ""
}
