//go:build !ios

package net

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/util"
	"github.com/netbirdio/netbird/client/net/hooks"
)

// ListenPacket listens on the network address and returns a PacketConn
// which includes support for write hooks.
func (l *ListenerConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if CustomRoutingDisabled() || AdvancedRouting() {
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
	if err := callWriteHooks(c.ID, c.seenAddrs, addr); err != nil {
		log.Errorf("Failed to call write hooks: %v", err)
	}
	return c.PacketConn.WriteTo(b, addr)
}

// Close overrides the net.PacketConn Close method to execute all registered hooks after closing the connection.
func (c *PacketConn) Close() error {
	defer c.seenAddrs.Clear()
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
	if err := callWriteHooks(c.ID, c.seenAddrs, addr); err != nil {
		log.Errorf("Failed to call write hooks: %v", err)
	}
	return c.UDPConn.WriteTo(b, addr)
}

// Close overrides the net.UDPConn Close method to execute all registered hooks after closing the connection.
func (c *UDPConn) Close() error {
	defer c.seenAddrs.Clear()
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

	prefix := netip.PrefixFrom(ipAddr.Unmap(), ipAddr.BitLen())

	addressRemoveHooks := hooks.GetAddressRemoveHooks()
	if len(addressRemoveHooks) == 0 {
		return
	}

	for _, hook := range addressRemoveHooks {
		if err := hook(c.ID, prefix); err != nil {
			log.Errorf("Error executing listener address remove hook: %v", err)
		}
	}
}

// WrapPacketConn wraps an existing net.PacketConn with nbnet hook functionality
func WrapPacketConn(conn net.PacketConn) net.PacketConn {
	if AdvancedRouting() {
		// hooks not required for advanced routing
		return conn
	}
	return &PacketConn{
		PacketConn: conn,
		ID:         hooks.GenerateConnID(),
		seenAddrs:  &sync.Map{},
	}
}

func callWriteHooks(id hooks.ConnectionID, seenAddrs *sync.Map, addr net.Addr) error {
	if _, loaded := seenAddrs.LoadOrStore(addr.String(), true); loaded {
		return nil
	}

	writeHooks := hooks.GetWriteHooks()
	if len(writeHooks) == 0 {
		return nil
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("expected *net.UDPAddr for packet connection, got %T", addr)
	}

	prefix, err := util.GetPrefixFromIP(udpAddr.IP)
	if err != nil {
		return fmt.Errorf("convert UDP IP %s to prefix: %w", udpAddr.IP, err)
	}

	log.Debugf("Listener resolved IP for %s: %s", addr, prefix)

	var merr *multierror.Error
	for _, hook := range writeHooks {
		if err := hook(id, prefix); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("execute write hook: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}
