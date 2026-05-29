//go:build windows

package mdm

// loadPlatformPolicy reads the MDM configuration from the Windows registry
// under HKLM\Software\Policies\NetBird. Phase 1 ships a stub; the real
// reader lands in Phase 3.
func loadPlatformPolicy() (map[string]any, error) {
	return nil, nil
}
