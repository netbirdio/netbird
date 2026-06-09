//go:build ios || android

package mdm

// loadPlatformPolicy is unused on mobile: the native layer (Swift on iOS,
// Kotlin/Java on Android) reads the OS managed-config store and pushes the
// resulting dictionary in-process via a gomobile entry point that lands in
// Phase 5 / Phase 6. The stub keeps the package compilable for mobile
// builds and returns (nil, nil) — the platform-absent sentinel that
// LoadPolicy in policy.go treats as "no MDM source present".
//
// loadPlatformPolicy reports the absence of a platform-managed configuration on mobile builds.
// It returns a nil policy map and a nil error as a sentinel value; the real managed-config
// dictionary is read by the native iOS/Android layer and injected into the Go process.
func loadPlatformPolicy() (map[string]any, error) {
	return nil, nil
}
