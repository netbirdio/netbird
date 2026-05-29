//go:build darwin && !ios

package mdm

// loadPlatformPolicy reads the MDM configuration from the macOS managed
// preferences plist. Phase 1 ships a stub; the real reader lands in Phase 2.
func loadPlatformPolicy() (map[string]any, error) {
	return nil, nil
}
