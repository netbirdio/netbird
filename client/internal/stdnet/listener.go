package stdnet

import (
	"context"
	"net"

	"github.com/pion/transport/v3"

	netpkg "github.com/netbirdio/netbird/pkg/net"
)

// ListenPacket listens for incoming packets on the given network and address.
func (n *Net) ListenPacket(network, address string) (net.PacketConn, error) {
	return netpkg.NewListener().ListenPacket(context.Background(), network, address)
}

// ListenUDP acts like ListenPacket for UDP networks.
func (n *Net) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	return netpkg.ListenUDP(network, locAddr)
}
