//go:build ios || android

package mdm

// loadPlatform reads the OS-managed configuration via the native
// PolicyFetcher injected at Loader construction. Returns
// (nil, nil) — the platform-absent sentinel that Loader.Load treats as
// "no MDM source present" — when no fetcher was provided.
func (l *Loader) loadPlatform() (map[string]any, error) {
	if l == nil || l.fetcher == nil {
		//nolint:nilnil // (nil, nil) is the documented platform-absent sentinel; see Loader.Load.
		return nil, nil
	}
	return l.fetcher.Fetch(), nil
}
