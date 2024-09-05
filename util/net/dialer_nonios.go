//go:build !ios

package net

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
)

type DialerDialHookFunc func(ctx context.Context, connID ConnectionID, resolvedAddresses []net.IPAddr) error
type DialerCloseHookFunc func(connID ConnectionID, conn *net.Conn) error

var (
	dialerDialHooksMutex  sync.RWMutex
	dialerDialHooks       []DialerDialHookFunc
	dialerCloseHooksMutex sync.RWMutex
	dialerCloseHooks      []DialerCloseHookFunc
)

// AddDialerHook allows adding a new hook to be executed before dialing.
func AddDialerHook(hook DialerDialHookFunc) {
	dialerDialHooksMutex.Lock()
	defer dialerDialHooksMutex.Unlock()
	dialerDialHooks = append(dialerDialHooks, hook)
}

// AddDialerCloseHook allows adding a new hook to be executed on connection close.
func AddDialerCloseHook(hook DialerCloseHookFunc) {
	dialerCloseHooksMutex.Lock()
	defer dialerCloseHooksMutex.Unlock()
	dialerCloseHooks = append(dialerCloseHooks, hook)
}

// RemoveDialerHooks removes all dialer hooks.
func RemoveDialerHooks() {
	dialerDialHooksMutex.Lock()
	defer dialerDialHooksMutex.Unlock()
	dialerDialHooks = nil

	dialerCloseHooksMutex.Lock()
	defer dialerCloseHooksMutex.Unlock()
	dialerCloseHooks = nil
}

// DialContext wraps the net.Dialer's DialContext method to use the custom connection
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if CustomRoutingDisabled() {
		return d.Dialer.DialContext(ctx, network, address)
	}

	var resolver *net.Resolver
	if d.Resolver != nil {
		resolver = d.Resolver
	}

	connID := GenerateConnID()
	if dialerDialHooks != nil {
		if err := callDialerHooks(ctx, connID, address, resolver); err != nil {
			log.Errorf("Failed to call dialer hooks: %v", err)
		}
	}

	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	// Wrap the connection in Conn to handle Close with hooks
	return &Conn{Conn: conn, ID: connID}, nil
}

// Dial wraps the net.Dialer's Dial method to use the custom connection
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// Conn wraps a net.Conn to override the Close method
type Conn struct {
	net.Conn
	ID ConnectionID
}

// Close overrides the net.Conn Close method to execute all registered hooks after closing the connection
func (c *Conn) Close() error {
	err := c.Conn.Close()

	dialerCloseHooksMutex.RLock()
	defer dialerCloseHooksMutex.RUnlock()

	for _, hook := range dialerCloseHooks {
		if err := hook(c.ID, &c.Conn); err != nil {
			log.Errorf("Error executing dialer close hook: %v", err)
		}
	}

	return err
}

func callDialerHooks(ctx context.Context, connID ConnectionID, address string, resolver *net.Resolver) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("split host and port: %w", err)
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to resolve address %s: %w", address, err)
	}

	log.Debugf("Dialer resolved IPs for %s: %v", address, ips)

	var result *multierror.Error

	dialerDialHooksMutex.RLock()
	defer dialerDialHooksMutex.RUnlock()
	for _, hook := range dialerDialHooks {
		if err := hook(ctx, connID, ips); err != nil {
			result = multierror.Append(result, fmt.Errorf("executing dial hook: %w", err))
		}
	}

	return result.ErrorOrNil()
}

func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if CustomRoutingDisabled() {
		return net.DialUDP(network, laddr, raddr)
	}

	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, fmt.Errorf("dialing UDP %s: %w", raddr.String(), err)
	}

	udpConn, ok := conn.(*Conn).Conn.(*net.UDPConn)
	if !ok {
		if err := conn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
		return nil, fmt.Errorf("expected UDP connection, got different type: %T", conn)
	}

	return udpConn, nil
}

func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	if CustomRoutingDisabled() {
		return net.DialTCP(network, laddr, raddr)
	}

	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, fmt.Errorf("dialing TCP %s: %w", raddr.String(), err)
	}

	tcpConn, ok := conn.(*Conn).Conn.(*net.TCPConn)
	if !ok {
		if err := conn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
		return nil, fmt.Errorf("expected TCP connection, got different type: %T", conn)
	}

	return tcpConn, nil
}
