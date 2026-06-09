//go:build !windows && !darwin && !ios && !android

package mdm

// loadPlatformPolicy returns no policy on platforms without an MDM channel
// (Linux, FreeBSD). MDM enforcement is off and the client behaves as if
// the feature did not exist. Returns (nil, nil) — the platform-absent
// sentinel the caller (LoadPolicy in policy.go) treats as "no MDM
// source present"; an error here would just translate to the same
// outcome with an extra log line.
//
// loadPlatformPolicy indicates that no platform MDM policy is available on this build target.
// It intentionally returns (nil, nil) as the documented platform-absent sentinel so callers treat MDM as not present.
func loadPlatformPolicy() (map[string]any, error) {
	return nil, nil
}
