package legacy

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

// Router defines the interface for legacy management operations
type Router interface {
	RemoveAllLegacyRouteRules() error
	GetLegacyManagement() bool
	SetLegacyManagement(bool)
}

// SetLegacyRouter sets the route manager to use legacy management
func SetLegacyRouter(router Router, isLegacy bool) error {
	oldLegacy := router.GetLegacyManagement()

	if oldLegacy != isLegacy {
		router.SetLegacyManagement(isLegacy)
		logrus.Debugf("Set legacy management to %v", isLegacy)
	}

	// client reconnected to a newer mgmt, we need to clean up the legacy rules
	if !isLegacy && oldLegacy {
		if err := router.RemoveAllLegacyRouteRules(); err != nil {
			return fmt.Errorf("remove legacy routing rules: %v", err)
		}

		logrus.Debugf("Legacy routing rules removed")
	}

	return nil
}
