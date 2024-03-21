package net

import (
	"context"
	"fmt"
	"net"
	"sync"

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

func (l *ListenerConfig) init() {
}

// ListenPacket listens on the network address and returns a PacketConn
// which includes support for write hooks.
func (l *ListenerConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	pc, err := l.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("listen packet: %w", err)
	}
	connID := GenerateConnID()
	return &PacketConn{PacketConn: pc, ID: connID, seenAddrs: &sync.Map{}}, nil
}

// PacketConn wraps net.PacketConn to override its WriteTo method
// to include write hook functionality.
type PacketConn struct {
	net.PacketConn
	ID        ConnectionID
	seenAddrs *sync.Map
}

// WriteTo writes a packet with payload b to addr, executing registered write hooks beforehand.
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// Lookup the address in the seenAddrs map to avoid calling the hooks for every write
	if _, loaded := c.seenAddrs.LoadOrStore(addr.String(), true); !loaded {
		ipStr, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			log.Errorf("Error splitting IP address and port: %v", splitErr)
			goto conn
		}

		ip, err := net.ResolveIPAddr("ip", ipStr)
		if err != nil {
			log.Errorf("Error resolving IP address: %v", err)
			goto conn
		}
		log.Debugf("Listener resolved IP for %s: %s", addr, ip)

		func() {
			listenerWriteHooksMutex.RLock()
			defer listenerWriteHooksMutex.RUnlock()

			for _, hook := range listenerWriteHooks {
				if err := hook(c.ID, ip, b); err != nil {
					log.Errorf("Error executing listener write hook: %v", err)
				}
			}
		}()
	}

conn:
	return c.PacketConn.WriteTo(b, addr)
}

// Close overrides the net.PacketConn Close method to execute all registered hooks before closing the connection.
func (c *PacketConn) Close() error {
	err := c.PacketConn.Close()

	listenerCloseHooksMutex.RLock()
	defer listenerCloseHooksMutex.RUnlock()

	for _, hook := range listenerCloseHooks {
		if err := hook(c.ID, c.PacketConn); err != nil {
			log.Errorf("Error executing listener close hook: %v", err)
		}
	}

	c.seenAddrs = &sync.Map{}

	return err
}
