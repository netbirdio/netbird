//go:build ios

package bind

func (m *UDPMuxDefault) notifyAddressRemoval(addr string) {
	// iOS doesn't support nbnet hooks, so this is a no-op
}
