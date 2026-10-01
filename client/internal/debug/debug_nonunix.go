//go:build !unix && !windows

package debug

func (g *BundleGenerator) addDNSInfo() error {
	return nil
}
