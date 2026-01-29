//go:build ios || tvos

package udpmux

func (m *SingleSocketUDPMux) notifyAddressRemoval(addr string) {
	// iOS doesn't support nbnet hooks, so this is a no-op
}
