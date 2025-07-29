//go:build !ios

package net

import (
	"context"
	"fmt"
	"net"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/net/hooks"
)

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

	connID := hooks.GenerateConnID()
	dialerDialHooks := hooks.GetDialerHooks()
	if dialerDialHooks != nil {
		if err := callDialerHooks(ctx, connID, address, resolver, dialerDialHooks); err != nil {
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

func callDialerHooks(ctx context.Context, connID hooks.ConnectionID, address string, resolver *net.Resolver, dialerDialHooks []hooks.DialerDialHookFunc) error {
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

	for _, hook := range dialerDialHooks {
		if err := hook(ctx, connID, ips); err != nil {
			result = multierror.Append(result, fmt.Errorf("executing dial hook: %w", err))
		}
	}

	return result.ErrorOrNil()
}
