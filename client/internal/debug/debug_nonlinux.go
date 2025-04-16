//go:build !linux || android

package debug

// collectFirewallRules returns nothing on non-linux systems
func (g *BundleGenerator) addFirewallRules() error {
	return nil
}
