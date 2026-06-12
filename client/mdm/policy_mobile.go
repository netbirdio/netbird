//go:build ios || android

package mdm

// PolicyFetcher is the bridge between Go and the mobile native layer
// (Kotlin/Java on Android, Swift on iOS). The native layer registers
// an implementation at gomobile init via SetMobilePolicyFetcher;
// thereafter every call to loadPlatformPolicy delegates to the
// registered fetcher, which reads the OS-native managed-config store
// (RestrictionsManager on Android, com.apple.configuration.managed
// UserDefaults on iOS) and returns the current snapshot.
//
// Set-once at init, never mutated at runtime → no synchronisation
// required for the read path. The native layer must register before
// any Go code starts polling or processing MDM events.
type PolicyFetcher interface {
	Fetch() map[string]any
}

var fetcher PolicyFetcher

// SetMobilePolicyFetcher registers the native-provided fetcher. Call
// exactly once from the gomobile init code (Kotlin Application.onCreate
// / Swift AppDelegate) before the daemon starts. Passing nil disables
// MDM enforcement on this build (loadPlatformPolicy returns
// (nil, nil) — the platform-absent sentinel that LoadPolicy treats as
// "no MDM source present").
func SetMobilePolicyFetcher(p PolicyFetcher) {
	fetcher = p
}

// loadPlatformPolicy delegates to the native-provided fetcher. Returns
// (nil, nil) — the platform-absent sentinel — when no fetcher has been
// registered yet, so the package behaves identically to a desktop
// device without an MDM source.
func loadPlatformPolicy() (map[string]any, error) {
	if fetcher == nil {
		//nolint:nilnil // (nil, nil) is the documented platform-absent sentinel; see LoadPolicy.
		return nil, nil
	}
	return fetcher.Fetch(), nil
}
