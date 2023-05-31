package internal

import (
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/iface"
)

// MobileDependency collect all dependencies for mobile platform
type MobileDependency struct {
	TunAdapter    iface.TunAdapter
	IFaceDiscover stdnet.ExternalIFaceDiscover
	RouteListener routemanager.RouteListener
}
