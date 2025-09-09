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

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func hasSeparateRouting() ([]netip.Prefix, error) {
	return GetRoutesFromTable()
}

// GetIPRules returns IP rules for debugging (not supported on non-Linux platforms)
func GetIPRules() ([]IPRule, error) {
	log.Infof("IP rules collection is not supported on %s", runtime.GOOS)
	return []IPRule{}, nil
}
