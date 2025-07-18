//go:build !ios

package bind

import (
	nbnet "github.com/netbirdio/netbird/util/net"
)

func (m *UDPMuxDefault) notifyAddressRemoval(addr string) {
	wrapped, ok := m.params.UDPConn.(*UDPConn)
	if !ok {
		return
	}

	nbnetConn, ok := wrapped.GetPacketConn().(*nbnet.UDPConn)
	if !ok {
		return
	}

	nbnetConn.RemoveAddress(addr)
}
