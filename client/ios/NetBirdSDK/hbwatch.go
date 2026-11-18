//go:build ios

package NetBirdSDK

import "github.com/netbirdio/netbird/client/hbwatch"

// CheckHeartbeatsNow asks the heartbeat stale check to look at every connected
// service after a short grace. The extension calls it from wake(). It is a
// no-op when the check is disabled, before the engine runs and after it stops.
func CheckHeartbeatsNow() {
	hbwatch.CheckNow()
}

// DeviceSleeping tells the heartbeat watcher that the device went to sleep.
// The extension calls it from sleep(). While the device sleeps and the tunnel
// is idle, Management reconnects wait for a heartbeat or a wake.
func DeviceSleeping() {
	hbwatch.SetDeviceAsleep(true)
}

// DeviceAwake tells the heartbeat watcher that the device woke up. The
// extension calls it from wake().
func DeviceAwake() {
	hbwatch.SetDeviceAsleep(false)
}
