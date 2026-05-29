//go:build ios || android

package mdm

// loadPlatformPolicy is unused on mobile: the native layer (Swift on iOS,
// Kotlin/Java on Android) reads the OS managed-config store and pushes the
// resulting dictionary in-process via a gomobile entry point that lands in
// Phase 5 / Phase 6. The stub keeps the package compilable for mobile
// build targets.
func loadPlatformPolicy() (map[string]any, error) {
	return nil, nil
}
