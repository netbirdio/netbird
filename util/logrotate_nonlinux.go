//go:build !linux

package util

// FindLogrotateConflicts scans the standard logrotate locations for
// indications of conflict with netbird. It will always return false for
// non-linux devices.
func FindFirstLogrotateConflict() (bool, string) {
	return false, ""
}
