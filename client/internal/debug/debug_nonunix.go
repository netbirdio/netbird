//go:build !unix

package debug

func (g *BundleGenerator) addDNSInfo() error {
	return nil
}
