//go:build !windows && !darwin && !ios && !android

package mdm

// loadPlatformPolicy returns no policy on platforms without an MDM channel
// (Linux, FreeBSD). MDM enforcement is off and the client behaves as if
// the feature did not exist.
func loadPlatformPolicy() (map[string]any, error) {
	return nil, nil
}
