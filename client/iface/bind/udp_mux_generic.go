//go:build !ios

package bind

import (
	"net"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func (m *UDPMuxDefault) notifyAddressRemoval(addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Errorf("Failed to parse UDP address %s: %v", addr, err)
		return
	}

	// Kernel mode: direct nbnet.PacketConn (SharedSocket wrapped with nbnet)
	if conn, ok := m.params.UDPConn.(*nbnet.PacketConn); ok {
		conn.RemoveAddress(udpAddr)
		return
	}

	// Userspace mode: UDPConn wrapper around nbnet.PacketConn
	if wrapped, ok := m.params.UDPConn.(*UDPConn); ok {
		if conn, ok := wrapped.GetPacketConn().(*nbnet.PacketConn); ok {
			conn.RemoveAddress(udpAddr)
		}
	}
}
