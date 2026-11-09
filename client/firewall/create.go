//go:build !linux || android

package firewall

import (
	"fmt"
	"runtime"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// NewFirewall creates a firewall manager instance
func NewFirewall(iface IFaceMapper, _ *statemanager.Manager, flowLogger nftypes.FlowLogger, disableServerRoutes bool, mtu uint16) (firewall.Manager, error) {
	if !iface.IsUserspaceBind() {
		return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
	}

	// use userspace packet filtering firewall
	return uspfilter.Create(uspfilter.Config{
		IFace:               iface,
		DisableServerRoutes: disableServerRoutes,
		FlowLogger:          flowLogger,
		MTU:                 mtu,
		InterfaceAllower:    interfaceAllower(iface, mtu),
	})
}
