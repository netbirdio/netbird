package stdnet

import (
	"net"

	transportv4 "github.com/pion/transport/v4"
	stdnetv4 "github.com/pion/transport/v4/stdnet"

	nbnet "github.com/netbirdio/netbird/client/net"
)

var _ transportv4.Net = (*NetV4)(nil)

// NetV4 is a pion transport/v4 Net for pion libraries that moved off transport/v3.
// Dials go through the NetBird dialer, so they bypass the overlay like Net does.
type NetV4 struct {
	*stdnetv4.Net
}

// NewNetV4 creates a transport/v4 Net backed by the NetBird dialer.
func NewNetV4() (*NetV4, error) {
	n, err := stdnetv4.NewNet()
	if err != nil {
		return nil, err
	}
	return &NetV4{Net: n}, nil
}

// Dial connects to the address on the named network.
func (n *NetV4) Dial(network, address string) (net.Conn, error) {
	return nbnet.NewDialer().Dial(network, address)
}

// DialUDP connects to the address on the named UDP network.
func (n *NetV4) DialUDP(network string, laddr, raddr *net.UDPAddr) (transportv4.UDPConn, error) {
	return nbnet.DialUDP(network, laddr, raddr)
}

// DialTCP connects to the address on the named TCP network.
func (n *NetV4) DialTCP(network string, laddr, raddr *net.TCPAddr) (transportv4.TCPConn, error) {
	return nbnet.DialTCP(network, laddr, raddr)
}
