//go:build !windows && !js && !ios && !android

package server

// isPipeDisconnect is Windows-only: other platforms have no named pipes, and
// their socket disconnects are covered by isProbeDisconnect.
func isPipeDisconnect(error) bool {
	return false
}
