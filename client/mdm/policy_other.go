//go:build !windows && !darwin && !ios && !android

package mdm

// loadPlatformPolicy returns no policy on platforms without an MDM channel
// (Linux, FreeBSD). MDM enforcement is off and the client behaves as if
// the feature did not exist. Returns (nil, nil) — the platform-absent
// sentinel the caller (LoadPolicy in policy.go) treats as "no MDM
// source present"; an error here would just translate to the same
// outcome with an extra log line.
func loadPlatformPolicy() (map[string]any, error) {
	//nolint:nilnil // (nil, nil) is the documented platform-absent sentinel; see LoadPolicy.
	return nil, nil
}
