//go:build android

package android

import "github.com/netbirdio/netbird/client/hbwatch"

// CheckHeartbeatsNow asks the heartbeat wake check to look at every
// connected service after a short grace. The app calls it when the
// device wakes. It is a no-op before the engine runs and after it
// stops, and on builds that do not ask for the aligned heartbeat.
func CheckHeartbeatsNow() {
	hbwatch.CheckNow()
}
