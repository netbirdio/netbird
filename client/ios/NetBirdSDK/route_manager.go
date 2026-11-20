//go:build darwin || ios

package NetBirdSDK

import (
	"fmt"

	"github.com/netbirdio/netbird/client/internal/routemanager"
)

func requireRouteManager(manager routemanager.Manager) (routemanager.Manager, error) {
	if manager == nil {
		return nil, fmt.Errorf("could not get route manager")
	}

	return manager, nil
}
