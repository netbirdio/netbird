package stdnet

import (
	"fmt"
	"net"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

// Dial connects to the address on the named network.
func (n *Net) Dial(network, address string) (net.Conn, error) {
	log.Tracef("ICE: Checking if address %s is routed", address)
	isRouted, prefix, err := addrViaRoutes(address, n.routes)

	if err != nil {
		log.Errorf("Failed to check if address %s is routed: %v", address, err)
	} else if isRouted {
		return nil, fmt.Errorf("[Dial] IP %s is part of routed network %s, refusing to dial", address, prefix)
	}
	return nbnet.NewDialer().Dial(network, address)
}

// DialUDP connects to the address on the named UDP network.
func (n *Net) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	log.Tracef("ICE: Checking if address %s is routed", raddr)
	isRouted, prefix, err := addrViaRoutes(raddr.IP.String(), n.routes)

	if err != nil {
		log.Errorf("Failed to check if address %s is routed: %v", raddr, err)
	} else if isRouted {
		return nil, fmt.Errorf("[Dial] IP %s is part of routed network %s, refusing to dial", raddr, prefix)
	}
	return nbnet.DialUDP(network, laddr, raddr)
}

// DialTCP connects to the address on the named TCP network.
func (n *Net) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	return nbnet.DialTCP(network, laddr, raddr)
}
