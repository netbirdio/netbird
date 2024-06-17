package stdnet

import (
	"net"

	"github.com/pion/transport/v3"

	nbnet "github.com/netbirdio/netbird/util/net"
)

// Dial connects to the address on the named network.
func (n *Net) Dial(network, address string) (net.Conn, error) {
	return nbnet.NewDialer().Dial(network, address)
}

// DialUDP connects to the address on the named UDP network.
func (n *Net) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	return nbnet.DialUDP(network, laddr, raddr)
}

// DialTCP connects to the address on the named TCP network.
func (n *Net) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	return nbnet.DialTCP(network, laddr, raddr)
}
