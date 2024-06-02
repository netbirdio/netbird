//go:build !ios

package net

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
)

// ListenerWriteHookFunc defines the function signature for write hooks for PacketConn.
type ListenerWriteHookFunc func(connID ConnectionID, ip *net.IPAddr, data []byte) error

// ListenerCloseHookFunc defines the function signature for close hooks for PacketConn.
type ListenerCloseHookFunc func(connID ConnectionID, conn net.PacketConn) error

var (
	listenerWriteHooksMutex sync.RWMutex
	listenerWriteHooks      []ListenerWriteHookFunc
	listenerCloseHooksMutex sync.RWMutex
	listenerCloseHooks      []ListenerCloseHookFunc
)

// AddListenerWriteHook allows adding a new write hook to be executed before a UDP packet is sent.
func AddListenerWriteHook(hook ListenerWriteHookFunc) {
	listenerWriteHooksMutex.Lock()
	defer listenerWriteHooksMutex.Unlock()
	listenerWriteHooks = append(listenerWriteHooks, hook)
}

// AddListenerCloseHook allows adding a new hook to be executed upon closing a UDP connection.
func AddListenerCloseHook(hook ListenerCloseHookFunc) {
	listenerCloseHooksMutex.Lock()
	defer listenerCloseHooksMutex.Unlock()
	listenerCloseHooks = append(listenerCloseHooks, hook)
}

// RemoveListenerHooks removes all dialer hooks.
func RemoveListenerHooks() {
	listenerWriteHooksMutex.Lock()
	defer listenerWriteHooksMutex.Unlock()
	listenerWriteHooks = nil

	listenerCloseHooksMutex.Lock()
	defer listenerCloseHooksMutex.Unlock()
	listenerCloseHooks = nil
}

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
	connID := GenerateConnID()
	return &PacketConn{PacketConn: pc, ID: connID, seenAddrs: &sync.Map{}}, nil
}

// PacketConn wraps net.PacketConn to override its WriteTo and Close methods to include hook functionality.
type PacketConn struct {
	net.PacketConn
	ID        ConnectionID
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
	ID        ConnectionID
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

func callWriteHooks(id ConnectionID, seenAddrs *sync.Map, b []byte, addr net.Addr) {
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

		func() {
			listenerWriteHooksMutex.RLock()
			defer listenerWriteHooksMutex.RUnlock()

			for _, hook := range listenerWriteHooks {
				if err := hook(id, ip, b); err != nil {
					log.Errorf("Error executing listener write hook: %v", err)
				}
			}
		}()
	}
}

func closeConn(id ConnectionID, conn net.PacketConn) error {
	err := conn.Close()

	listenerCloseHooksMutex.RLock()
	defer listenerCloseHooksMutex.RUnlock()

	for _, hook := range listenerCloseHooks {
		if err := hook(id, conn); err != nil {
			log.Errorf("Error executing listener close hook: %v", err)
		}
	}

	return err
}

// ListenUDP listens on the network address and returns a transport.UDPConn
// which includes support for write and close hooks.
func ListenUDP(network string, laddr *net.UDPAddr) (transport.UDPConn, error) {
	if CustomRoutingDisabled() {
		return net.ListenUDP(network, laddr)
	}

	conn, err := NewListener().ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	packetConn := conn.(*PacketConn)
	udpConn, ok := packetConn.PacketConn.(*net.UDPConn)
	if !ok {
		if err := packetConn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
		return nil, fmt.Errorf("expected UDPConn, got different type: %T", udpConn)
	}

	return &UDPConn{UDPConn: udpConn, ID: packetConn.ID, seenAddrs: &sync.Map{}}, nil
}
