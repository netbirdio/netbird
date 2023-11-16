package routemanager

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/iface"
)

func newServerRouter(context.Context, *iface.WGIface, firewall firewall.Manager) (serverRouter, error) {
	return nil, fmt.Errorf("server route not supported on this os")
}
