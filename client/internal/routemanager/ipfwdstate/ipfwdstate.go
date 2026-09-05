package ipfwdstate

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// IPForwardingState tracks v4 and v6 IP-forwarding sysctl enables with
// independent refcounts so a v4-only routing setup doesn't flip v6 sysctls.
type IPForwardingState struct {
	mu sync.Mutex

	v4Count int
	v6Count int

	// routingV4/routingV6 track whether the routing path currently holds a
	// reference, so repeated EnableRouting calls (one per network-map update)
	// hold at most one reference per family and an unpaired DisableRouting
	// can't release references held by DNAT rules.
	routingV4 bool
	routingV6 bool

	wgIfaceName string
	v6Saved     map[string]int
}

// NewIPForwardingState returns a state tracker for the IP-forwarding sysctls.
// wgIfaceName is excluded from the per-interface accept_ra handling.
func NewIPForwardingState(wgIfaceName string) *IPForwardingState {
	return &IPForwardingState{wgIfaceName: wgIfaceName}
}

// Counts returns the current v4 and v6 refcounts. Intended for diagnostics
// and tests.
func (f *IPForwardingState) Counts() (v4, v6 int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.v4Count, f.v6Count
}

// RequestRouting takes the forwarding references for the routing path. It is
// idempotent: while routing already holds a reference, further calls don't
// increment the refcounts, and a v4-only request releases a previously held v6
// reference. A v6 sysctl failure is logged and not returned so it can't take
// down v4 routing (the sysctl may be unwritable, e.g. read-only /proc/sys or
// IPv6 disabled on the kernel command line); v6 is retried on the next call.
func (f *IPForwardingState) RequestRouting(v6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.routingV4 {
		if err := f.requestV4(); err != nil {
			return err
		}
		f.routingV4 = true
	}

	if !v6 {
		if !f.routingV6 {
			return nil
		}
		f.routingV6 = false
		return f.releaseV6()
	}

	if f.routingV6 {
		return nil
	}
	if err := f.requestV6(); err != nil {
		log.Warnf("enable IPv6 forwarding for routing: %v", err)
		return nil
	}
	f.routingV6 = true
	return nil
}

// ReleaseRouting releases the references RequestRouting holds. Calls without a
// held reference are no-ops.
func (f *IPForwardingState) ReleaseRouting() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.routingV4 {
		f.routingV4 = false
		f.releaseV4()
	}
	if f.routingV6 {
		f.routingV6 = false
		return f.releaseV6()
	}
	return nil
}

// RequestForwarding enables the family's forwarding sysctl on first request.
func (f *IPForwardingState) RequestForwarding(v6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if v6 {
		return f.requestV6()
	}
	return f.requestV4()
}

// ReleaseForwarding decrements the family counter. The last v6 release restores
// what enable captured. v4 stays on: net.ipv4.ip_forward is co-owned by other
// tooling (docker, k8s, libvirt).
func (f *IPForwardingState) ReleaseForwarding(v6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if v6 {
		return f.releaseV6()
	}
	f.releaseV4()
	return nil
}

func (f *IPForwardingState) requestV4() error {
	if f.v4Count == 0 {
		if err := systemops.EnableV4IPForwarding(); err != nil {
			return fmt.Errorf("enable IPv4 forwarding: %w", err)
		}
		log.Info("IPv4 forwarding enabled")
	}
	f.v4Count++
	return nil
}

func (f *IPForwardingState) releaseV4() {
	if f.v4Count > 0 {
		f.v4Count--
	}
}

func (f *IPForwardingState) requestV6() error {
	if f.v6Count == 0 {
		saved, err := systemops.EnableV6IPForwarding(f.wgIfaceName)
		if err != nil {
			if rerr := systemops.DisableV6IPForwarding(saved); rerr != nil {
				log.Warnf("rollback partial v6 sysctls: %v", rerr)
			}
			return fmt.Errorf("enable IPv6 forwarding: %w", err)
		}
		// A failed restore on a previous release keeps its saved values; those
		// are the true originals, so keep them over what this enable captured.
		if f.v6Saved == nil {
			f.v6Saved = saved
		} else {
			for k, v := range saved {
				if _, ok := f.v6Saved[k]; !ok {
					f.v6Saved[k] = v
				}
			}
		}
		log.Info("IPv6 forwarding enabled")
	}
	f.v6Count++
	return nil
}

func (f *IPForwardingState) releaseV6() error {
	if f.v6Count == 0 {
		return nil
	}
	f.v6Count--
	if f.v6Count > 0 {
		return nil
	}

	// Keep the saved values on failure so a later release or enable/release
	// cycle can still restore them; re-restoring an already-restored key is a
	// no-op since the sysctl already holds the desired value.
	if err := systemops.DisableV6IPForwarding(f.v6Saved); err != nil {
		return fmt.Errorf("disable IPv6 forwarding: %w", err)
	}
	f.v6Saved = nil
	log.Info("IPv6 forwarding disabled")
	return nil
}
