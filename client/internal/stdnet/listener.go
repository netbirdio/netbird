package stdnet

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/route"
	nbnet "github.com/netbirdio/netbird/util/net"
)

// ListenPacket listens for incoming packets on the given network and address.
func (n *Net) ListenPacket(network, address string) (net.PacketConn, error) {
	listener := nbnet.NewListener()
	pc, err := listener.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, fmt.Errorf("listen packet: %w", err)
	}
	return &PacketConn{PacketConn: pc, routes: n.routes}, nil
}

// ListenUDP acts like ListenPacket for UDP networks.
func (n *Net) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	udpConn, err := nbnet.ListenUDP(network, locAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	return &UDPConn{UDPConn: udpConn, routes: n.routes}, nil
}

type PacketConn struct {
	net.PacketConn
	routes    route.HAMap
	seenAddrs sync.Map
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	isRouted, err := isRouted(addr, &c.seenAddrs, c.routes)
	if err != nil {
		log.Errorf("Failed to check if address %s is routed: %v", addr, err)
	} else if isRouted {
		return 0, fmt.Errorf("[PacketConn] IP %s is part of routed network, refusing to write", addr)
	}

	return c.PacketConn.WriteTo(b, addr)
}

type UDPConn struct {
	transport.UDPConn
	routes    route.HAMap
	seenAddrs sync.Map
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	isRouted, err := isRouted(addr, &c.seenAddrs, c.routes)
	if err != nil {
		log.Errorf("Failed to check if address %s is routed: %v", addr, err)
	} else if isRouted {
		return 0, fmt.Errorf("[UDPConn] IP %s is part of routed network, refusing to write", addr)
	}

	return c.UDPConn.WriteTo(b, addr)
}

func isRouted(addr net.Addr, seenAddrs *sync.Map, routes route.HAMap) (bool, error) {
	log.Tracef("ICE: Checking if address %s is routed", addr.String())
	if isRouted, ok := seenAddrs.Load(addr.String()); ok {
		return isRouted.(bool), nil
	}

	isRouted, _, err := addrViaRoutes(addr.String(), routes)
	if err != nil {
		return false, err
	}

	seenAddrs.Store(addr.String(), isRouted)
	return isRouted, nil
}
