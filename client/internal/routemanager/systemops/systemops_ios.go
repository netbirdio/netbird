//go:build ios

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func (r *SysOps) SetupRouting([]net.IP) (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prefixes = make(map[netip.Prefix]struct{})
	return nil, nil, nil
}

func (r *SysOps) CleanupRouting() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.prefixes = make(map[netip.Prefix]struct{})
	r.notify()
	return nil
}

func (r *SysOps) AddVPNRoute(prefix netip.Prefix, _ *net.Interface) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.prefixes[prefix] = struct{}{}
	r.notify()
	return nil
}

func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, _ *net.Interface) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.prefixes, prefix)
	r.notify()
	return nil
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func IsAddrRouted(netip.Addr, []netip.Prefix) (bool, netip.Prefix) {
	return false, netip.Prefix{}
}

func (r *SysOps) notify() {
	prefixes := make([]netip.Prefix, 0, len(r.prefixes))
	for prefix := range r.prefixes {
		prefixes = append(prefixes, prefix)
	}
	r.notifier.OnNewPrefixes(prefixes)
}
