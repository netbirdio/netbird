//go:build !ios

package bind

import (
	"net"

	log "github.com/sirupsen/logrus"

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

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Errorf("Failed to parse UDP address %s: %v", addr, err)
		return
	}

	nbnetConn.RemoveAddress(udpAddr)
}
