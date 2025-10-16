package networkmonitor

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	// No-op for WASM - network changes don't apply
	return nil
}
