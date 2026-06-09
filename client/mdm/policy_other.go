//go:build !windows && !darwin && !ios && !android

package mdm

// loadPlatformPolicy returns no policy on platforms without an MDM channel
// (Linux, FreeBSD). MDM enforcement is off and the client behaves as if
// loadPlatformPolicy reports that no platform MDM policy is available on non-Windows/Darwin/iOS/Android builds.
// It returns a nil policy map and a nil error to indicate MDM enforcement is not present on this platform.
func loadPlatformPolicy() (map[string]any, error) {
	return nil, nil
}
