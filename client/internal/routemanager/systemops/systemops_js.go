package systemops

import (
	"errors"
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

var ErrRouteNotSupported = errors.New("route operations not supported on js")

func (r *SysOps) addToRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return ErrRouteNotSupported
}

func (r *SysOps) removeFromRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return ErrRouteNotSupported
}

func GetRoutesFromTable() ([]netip.Prefix, error) {
	return []netip.Prefix{}, nil
}

func hasSeparateRouting() ([]netip.Prefix, error) {
	return []netip.Prefix{}, nil
}

// GetDetailedRoutesFromTable returns empty routes for WASM.
func GetDetailedRoutesFromTable() ([]DetailedRoute, error) {
	return []DetailedRoute{}, nil
}

func (r *SysOps) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return ErrRouteNotSupported
}

func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return ErrRouteNotSupported
}

func (r *SysOps) SetupRouting(initAddresses []net.IP, stateManager *statemanager.Manager) error {
	return nil
}

func (r *SysOps) CleanupRouting(stateManager *statemanager.Manager) error {
	return nil
}
