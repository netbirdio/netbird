package firewall

import (
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
)

// InstallDNSHooksFilter installs a device filter that carries nothing but the
// DNS interception hooks, for setups that run no firewall manager. The
// in-process resolver receives queries through hooks on the interface's device
// filter, so without a filter it never sees a query; the filter passes all
// other traffic through untouched.
//
// It is a no-op when the interface has no device filter to install on, which
// is the case for a kernel bind.
func InstallDNSHooksFilter(iface IFaceMapper) error {
	if !iface.IsUserspaceBind() {
		return nil
	}

	return iface.SetFilter(&uspfilter.HooksFilter{})
}
