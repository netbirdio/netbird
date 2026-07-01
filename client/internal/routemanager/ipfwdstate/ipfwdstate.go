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

	wgIfaceName string
	v6Saved     map[string]int
}

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
		f.v6Saved = saved
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
