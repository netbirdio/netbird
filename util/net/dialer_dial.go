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
	log.Debugf("Dialing %s %s", network, address)

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
		return nil, fmt.Errorf("d.Dialer.DialContext: %w", err)
	}

	// Wrap the connection in Conn to handle Close with hooks
	return &Conn{Conn: conn, ID: connID}, nil
}

// Dial wraps the net.Dialer's Dial method to use the custom connection
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
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
