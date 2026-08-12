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

func (r *SysOps) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}
	return r.genericAddVPNRoute(prefix, intf)
}

func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}
	return r.genericRemoveVPNRoute(prefix, intf)
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
