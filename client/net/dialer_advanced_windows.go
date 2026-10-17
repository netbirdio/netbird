package net

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	minDialAttemptTimeout = 2 * time.Second
	maxDialAttemptTimeout = 8 * time.Second
)

// dialAdvanced dials with IP_UNICAST_IF binding. When multiple interfaces have a
// route to the destination, it tries each candidate in route-priority order with
// a split timeout so a metric-preferred but non-working NIC (e.g. Ethernet
// without upstream connectivity) does not exhaust the whole dial deadline
// before a working alternate (e.g. Wi-Fi) is attempted.
func (d *Dialer) dialAdvanced(ctx context.Context, network, address string) (net.Conn, error) {
	ifaces, dest, err := d.candidateInterfacesForDial(ctx, network, address)
	if err != nil || len(ifaces) <= 1 {
		if err != nil {
			log.Debugf("advanced dial fallback unavailable for %s: %v", address, err)
		}
		return d.Dialer.DialContext(ctx, network, address)
	}

	var lastErr error
	for i, iface := range ifaces {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("%w (last dial error: %v)", err, lastErr)
			}
			return nil, err
		}

		attemptTimeout := dialAttemptTimeout(ctx, len(ifaces)-i)
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		conn, dialErr := d.dialViaInterface(attemptCtx, network, address, dest, iface)
		cancel()
		if dialErr == nil {
			if i > 0 {
				// Avoid logging hostnames above debug; interface identity is enough.
				log.Infof("advanced dial succeeded via fallback interface %s (index %d) after %d failed attempt(s)",
					iface.Name, iface.Index, i)
			}
			return conn, nil
		}

		log.Debugf("dial %s %s via interface %s (index %d) failed: %v", network, address, iface.Name, iface.Index, dialErr)
		lastErr = dialErr
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no interface candidates for %s", address)
	}
	return nil, lastErr
}

func (d *Dialer) candidateInterfacesForDial(ctx context.Context, network, address string) ([]*net.Interface, netip.Addr, error) {
	if GetCandidateInterfacesFunc == nil {
		return nil, netip.Addr{}, fmt.Errorf("GetCandidateInterfacesFunc not initialized")
	}

	dest, err := parseDestinationAddressContext(ctx, network, address, d.Resolver)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	dest = dest.Unmap()
	if !dest.IsValid() {
		return nil, netip.Addr{}, fmt.Errorf("invalid destination address for %s", address)
	}

	ifaces, err := GetCandidateInterfacesFunc(dest, GetVPNInterfaceName())
	if err != nil {
		return nil, dest, err
	}
	return ifaces, dest, nil
}

func (d *Dialer) dialViaInterface(ctx context.Context, network, address string, dest netip.Addr, iface *net.Interface) (net.Conn, error) {
	attempt := &net.Dialer{
		Timeout:   d.Timeout,
		Deadline:  d.Deadline,
		KeepAlive: d.KeepAlive,
		Resolver:  d.Resolver,
	}

	selection := selectionForInterface(dest, iface)
	attempt.Control = func(network, address string, c syscall.RawConn) error {
		var controlErr error
		if err := c.Control(func(fd uintptr) {
			controlErr = setUnicastIf(fd, network, selection, address)
		}); err != nil {
			return fmt.Errorf("control: %w", err)
		}
		return controlErr
	}

	return attempt.DialContext(ctx, network, address)
}

func selectionForInterface(dest netip.Addr, iface *net.Interface) *interfaceSelection {
	if dest.Is6() {
		return &interfaceSelection{iface6: iface, iface4: iface}
	}
	return &interfaceSelection{iface4: iface}
}

func dialAttemptTimeout(ctx context.Context, remainingAttempts int) time.Duration {
	if remainingAttempts < 1 {
		remainingAttempts = 1
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		return maxDialAttemptTimeout
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Millisecond
	}

	per := remaining / time.Duration(remainingAttempts)
	if per < minDialAttemptTimeout {
		// Keep enough time for at least one more attempt when possible.
		if remaining < minDialAttemptTimeout {
			return remaining
		}
		return minDialAttemptTimeout
	}
	if per > maxDialAttemptTimeout {
		return maxDialAttemptTimeout
	}
	return per
}
