//go:build !windows && !darwin && !ios && !android

package mdm

// loadPlatform reads the MDM policy on platforms without a native MDM
// channel (Linux, FreeBSD). When no fetcher was injected the policy is
// (nil, nil) — the platform-absent sentinel that Loader.Load treats as
// "MDM enforcement disabled". A non-nil fetcher takes precedence: it
// is the test-seam used by unit tests to inject a scripted policy
// without touching the OS, and the same hook supports any future
// non-mobile OS that grows an out-of-band MDM channel.
func (l *Loader) loadPlatform() (map[string]any, error) {
	if l != nil && l.fetcher != nil {
		return l.fetcher.Fetch(), nil
	}
	//nolint:nilnil // (nil, nil) is the documented platform-absent sentinel; see Loader.Load.
	return nil, nil
}
