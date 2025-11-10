//go:build !ios

package net

import (
	"context"
	"fmt"
	"net"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/util"
	"github.com/netbirdio/netbird/client/net/hooks"
)

// DialContext wraps the net.Dialer's DialContext method to use the custom connection
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	log.Debugf("Dialing %s %s", network, address)

	if CustomRoutingDisabled() || AdvancedRouting() {
		return d.Dialer.DialContext(ctx, network, address)
	}

	connID := hooks.GenerateConnID()
	if err := callDialerHooks(ctx, connID, address, d.Resolver); err != nil {
		log.Errorf("Failed to call dialer hooks: %v", err)
	}

	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		cleanupConnID(connID)
		return nil, fmt.Errorf("d.Dialer.DialContext: %w", err)
	}

	// Wrap the connection in Conn to handle Close with hooks
	return &Conn{Conn: conn, ID: connID}, nil
}

// Dial wraps the net.Dialer's Dial method to use the custom connection
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func callDialerHooks(ctx context.Context, connID hooks.ConnectionID, address string, customResolver *net.Resolver) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	writeHooks := hooks.GetWriteHooks()
	if len(writeHooks) == 0 {
		return nil
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("split host and port: %w", err)
	}

	resolver := customResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve address %s: %w", address, err)
	}

	log.Debugf("Dialer resolved IPs for %s: %v", address, ips)

	var merr *multierror.Error
	for _, ip := range ips {
		prefix, err := util.GetPrefixFromIP(ip.IP)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("convert IP %s to prefix: %w", ip.IP, err))
			continue
		}
		for _, hook := range writeHooks {
			if err := hook(connID, prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("executing dial hook for IP %s: %w", ip.IP, err))
			}
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}
