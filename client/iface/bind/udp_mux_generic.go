//go:build !ios

package bind

import (
	nbnet "github.com/netbirdio/netbird/client/net"
)

func (m *UDPMuxDefault) notifyAddressRemoval(addr string) {
	// Kernel mode: direct nbnet.PacketConn (SharedSocket wrapped with nbnet)
	if conn, ok := m.params.UDPConn.(*nbnet.PacketConn); ok {
		conn.RemoveAddress(addr)
		return
	}

	// Userspace mode: UDPConn wrapper around nbnet.PacketConn
	if wrapped, ok := m.params.UDPConn.(*UDPConn); ok {
		if conn, ok := wrapped.GetPacketConn().(*nbnet.PacketConn); ok {
			conn.RemoveAddress(addr)
		}
	}
}
