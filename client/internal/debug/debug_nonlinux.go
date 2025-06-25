//go:build !linux || android

package debug

// collectFirewallRules returns nothing on non-linux systems
func (g *BundleGenerator) addFirewallRules() error {
	return nil
}

func (g *BundleGenerator) trySystemdLogFallback() error {
	// Systemd is only available on Linux
	// TODO: Add BSD support
	return nil
}
