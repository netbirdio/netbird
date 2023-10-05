//go:build ios

package routemanager

import (
	"context"
)

// newFirewall returns a nil manager
func newFirewall(context.Context) (firewallManager, error) {
	return iOSFirewallManager{}, nil
}

type iOSFirewallManager struct {
}

func (i iOSFirewallManager) RestoreOrCreateContainers() error {
	return nil
}

func (i iOSFirewallManager) InsertRoutingRules(pair routerPair) error {
	return nil
}

func (i iOSFirewallManager) RemoveRoutingRules(pair routerPair) error {
	return nil
}

func (i iOSFirewallManager) CleanRoutingRules() {
	return
}
