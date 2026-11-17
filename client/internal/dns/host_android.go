package dns

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// androidHostManager is a noop on the OS side (Android's VPN service handles
// DNS for us) but tracks the OS-reported resolver list pushed via
// OnUpdatedHostDNSServer so it can serve as the fallback nameserver source.
type androidHostManager struct {
	holder *hostsDNSHolder
}

func newHostManager(holder *hostsDNSHolder) (*androidHostManager, error) {
	return &androidHostManager{holder: holder}, nil
}

func (a androidHostManager) applyDNSConfig(HostDNSConfig, *statemanager.Manager) error {
	return nil
}

func (a androidHostManager) restoreHostDNS() error {
	return nil
}

func (a androidHostManager) supportCustomPort() bool {
	return false
}

func (a androidHostManager) string() string {
	return "none"
}

func (a androidHostManager) getOriginalNameservers() []netip.Addr {
	hosts := a.holder.get()
	out := make([]netip.Addr, 0, len(hosts))
	for ap := range hosts {
		out = append(out, ap.Addr())
	}
	return out
}
