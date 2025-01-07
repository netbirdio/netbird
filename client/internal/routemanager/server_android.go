//go:build android

package routemanager

import (
	"context"
	"fmt"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
)

type serverRouter struct {
}

func (r serverRouter) cleanUp() {
}

func (r serverRouter) updateRoutes(map[route.ID]*route.Route) error {
	return nil
}

func newServerRouter(context.Context, iface.IWGIface, firewall.Manager, *peer.Status) (*serverRouter, error) {
	return nil, fmt.Errorf("server route not supported on this os")
}
