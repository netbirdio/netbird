//go:build !windows

package auth

// getSystemExcludedPortRanges returns nil on non-Windows platforms.
func getSystemExcludedPortRanges() []excludedPortRange {
	return nil
}
