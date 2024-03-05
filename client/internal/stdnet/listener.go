package stdnet

import (
	"context"
	"net"

	"github.com/pion/transport/v3"

	nbnet "github.com/netbirdio/netbird/util/net"
)

// ListenPacket listens for incoming packets on the given network and address.
func (n *Net) ListenPacket(network, address string) (net.PacketConn, error) {
	return nbnet.NewListener().ListenPacket(context.Background(), network, address)
}

// ListenUDP acts like ListenPacket for UDP networks.
func (n *Net) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	return nbnet.ListenUDP(network, locAddr)
}
