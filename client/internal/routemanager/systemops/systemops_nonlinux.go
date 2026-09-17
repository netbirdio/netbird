//go:build !linux && !ios && !js

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// IPRule contains IP rule information for debugging
type IPRule struct {
	Priority     int
	From         netip.Prefix
	To           netip.Prefix
	IIF          string
	OIF          string
	Table        string
	Action       string
	Mark         uint32
	Mask         uint32
	TunID        uint32
	Goto         uint32
	Flow         uint32
	SuppressPlen int
	SuppressIFL  int
	Invert       bool
}

// AddVPNRoute adds a route for the prefix over the VPN interface, unless the prefix is
// contained in a locally attached subnet. The host already reaches such a subnet over its own
// link, so the route is withheld rather than installed where it would shadow that link.
// Withheld prefixes stay counted by the caller's refcounter with no OS route, and are
// converged later by ReconcileLocalSubnets. Unverified discovery fails closed the same way
// rather than installing over a subnet the cache missed.
func (r *SysOps) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}

	if subnet, overlap, healthy := r.localSubnetOverlap(prefix); !healthy || overlap {
		if !healthy {
			log.Warnf("Withholding VPN route %s: local-subnet discovery unverified, failing closed", prefix)
		} else {
			log.Debugf("Skipping VPN route %s: overlaps local subnet %s", prefix, subnet)
		}
		r.suppressVPNRoute(prefix, intf)
		return nil
	}

	if err := r.genericAddVPNRoute(prefix, intf); err != nil {
		return err
	}
	return nil
}

func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}
	if r.takeSuppressedVPNRoute(prefix) {
		return nil
	}
	if err := r.genericRemoveVPNRoute(prefix, intf); err != nil {
		return err
	}
	return nil
}

func EnableV4IPForwarding() error {
	log.Infof("Enable IPv4 forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func EnableV6IPForwarding(string) (map[string]int, error) {
	log.Infof("Enable IPv6 forwarding is not implemented on %s", runtime.GOOS)
	return map[string]int{}, nil
}

func DisableV6IPForwarding(map[string]int) error {
	return nil
}

// GetIPRules returns IP rules for debugging (not supported on non-Linux platforms)
func GetIPRules() ([]IPRule, error) {
	log.Infof("IP rules collection is not supported on %s", runtime.GOOS)
	return []IPRule{}, nil
}
