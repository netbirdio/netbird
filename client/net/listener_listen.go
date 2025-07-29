//go:build !ios

package net

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/net/hooks"
)

// ListenPacket listens on the network address and returns a PacketConn
// which includes support for write hooks.
func (l *ListenerConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if CustomRoutingDisabled() {
		return l.ListenConfig.ListenPacket(ctx, network, address)
	}

	pc, err := l.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("listen packet: %w", err)
	}
	connID := hooks.GenerateConnID()

	return &PacketConn{PacketConn: pc, ID: connID, seenAddrs: &sync.Map{}}, nil
}

// PacketConn wraps net.PacketConn to override its WriteTo and Close methods to include hook functionality.
type PacketConn struct {
	net.PacketConn
	ID        hooks.ConnectionID
	seenAddrs *sync.Map
}

// WriteTo writes a packet with payload b to addr, executing registered write hooks beforehand.
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	callWriteHooks(c.ID, c.seenAddrs, b, addr)
	return c.PacketConn.WriteTo(b, addr)
}

// Close overrides the net.PacketConn Close method to execute all registered hooks before closing the connection.
func (c *PacketConn) Close() error {
	c.seenAddrs = &sync.Map{}
	return closeConn(c.ID, c.PacketConn)
}

// UDPConn wraps net.UDPConn to override its WriteTo and Close methods to include hook functionality.
type UDPConn struct {
	*net.UDPConn
	ID        hooks.ConnectionID
	seenAddrs *sync.Map
}

// WriteTo writes a packet with payload b to addr, executing registered write hooks beforehand.
func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	callWriteHooks(c.ID, c.seenAddrs, b, addr)
	return c.UDPConn.WriteTo(b, addr)
}

// Close overrides the net.UDPConn Close method to execute all registered hooks before closing the connection.
func (c *UDPConn) Close() error {
	c.seenAddrs = &sync.Map{}
	return closeConn(c.ID, c.UDPConn)
}

// RemoveAddress removes an address from the seen cache and triggers removal hooks.
func (c *PacketConn) RemoveAddress(addr string) {
	if _, exists := c.seenAddrs.LoadAndDelete(addr); !exists {
		return
	}

	ipStr, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Errorf("Error splitting IP address and port: %v", err)
		return
	}

	ipAddr, err := netip.ParseAddr(ipStr)
	if err != nil {
		log.Errorf("Error parsing IP address %s: %v", ipStr, err)
		return
	}

	prefix := netip.PrefixFrom(ipAddr, ipAddr.BitLen())

	listenerAddressRemoveHooks := hooks.GetListenerAddressRemoveHooks()
	for _, hook := range listenerAddressRemoveHooks {
		if err := hook(c.ID, prefix); err != nil {
			log.Errorf("Error executing listener address remove hook: %v", err)
		}
	}
}

// WrapPacketConn wraps an existing net.PacketConn with nbnet functionality
func WrapPacketConn(conn net.PacketConn) *PacketConn {
	return &PacketConn{
		PacketConn: conn,
		ID:         hooks.GenerateConnID(),
		seenAddrs:  &sync.Map{},
	}
}

func callWriteHooks(id hooks.ConnectionID, seenAddrs *sync.Map, b []byte, addr net.Addr) {
	// Lookup the address in the seenAddrs map to avoid calling the hooks for every write
	if _, loaded := seenAddrs.LoadOrStore(addr.String(), true); !loaded {
		ipStr, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			log.Errorf("Error splitting IP address and port: %v", splitErr)
			return
		}

		ip, err := net.ResolveIPAddr("ip", ipStr)
		if err != nil {
			log.Errorf("Error resolving IP address: %v", err)
			return
		}
		log.Debugf("Listener resolved IP for %s: %s", addr, ip)

		listenerWriteHooks := hooks.GetListenerWriteHooks()
		for _, hook := range listenerWriteHooks {
			if err := hook(id, ip, b); err != nil {
				log.Errorf("Error executing listener write hook: %v", err)
			}
		}
	}
}

func closeConn(id hooks.ConnectionID, conn net.PacketConn) error {
	err := conn.Close()

	listenerCloseHooks := hooks.GetListenerCloseHooks()
	for _, hook := range listenerCloseHooks {
		if err := hook(id, conn); err != nil {
			log.Errorf("Error executing listener close hook: %v", err)
		}
	}

	return err
}
