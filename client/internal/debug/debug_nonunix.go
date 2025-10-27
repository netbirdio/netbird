//go:build !unix || android

package debug

func (g *BundleGenerator) addDNSInfo() error {
	return nil
}
