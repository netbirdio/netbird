package ipfwdstate

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// IPForwardingState tracks per-family IP-forwarding sysctl enables with a
// refcount. v4 and v6 are independent so a v4-only routing setup doesn't flip
// net.ipv6.conf.all.forwarding, which on Linux disables RA acceptance by
// default and lets host RA-installed defaults silently expire.
type IPForwardingState struct {
	mu sync.Mutex

	v4Count int
	v6Count int

	// wgIfaceName is excluded from the v6 accept_ra bump since the overlay
	// interface doesn't carry upstream RAs.
	wgIfaceName string
	// v6Saved records the sysctl values captured when v6 forwarding was
	// enabled (forwarding + per-interface accept_ra), restored on the last
	// release.
	v6Saved map[string]int
}

func NewIPForwardingState(wgIfaceName string) *IPForwardingState {
	return &IPForwardingState{wgIfaceName: wgIfaceName}
}

// RequestForwarding bumps the per-family counter, enabling the underlying
// sysctl on the first request.
func (f *IPForwardingState) RequestForwarding(v6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if v6 {
		return f.requestV6()
	}
	return f.requestV4()
}

// ReleaseForwarding decrements the per-family counter. The last v6 release
// also restores the sysctls v6 enable captured. v4 stays on: net.ipv4.ip_forward
// is a global knob other tools (docker, k8s, libvirt) co-own.
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
		f.v6Saved = saved
		if err != nil {
			return fmt.Errorf("enable IPv6 forwarding: %w", err)
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

	saved := f.v6Saved
	f.v6Saved = nil
	if err := systemops.DisableV6IPForwarding(saved); err != nil {
		return fmt.Errorf("disable IPv6 forwarding: %w", err)
	}
	log.Info("IPv6 forwarding disabled")
	return nil
}
