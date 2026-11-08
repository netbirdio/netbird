//go:build ios

package NetBirdSDK

import "github.com/netbirdio/netbird/client/hbwatch"

// CheckHeartbeatsNow asks the heartbeat stale check to look at every connected
// service after a short grace. The extension calls it from wake(). It is a
// no-op when the check is disabled, before the engine runs and after it stops.
func CheckHeartbeatsNow() {
	hbwatch.CheckNow()
}
