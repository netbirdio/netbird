package routemanager

import (
	"context"

	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

type serverRouter struct {
}

func newServerRouter(ctx context.Context, wgInterface *iface.WGIface) *serverRouter {
	return &serverRouter{}
}

func (r *serverRouter) updateRoutes(routesMap map[string]*route.Route) error {
	return nil
}

func (r *serverRouter) cleanUp() {}
