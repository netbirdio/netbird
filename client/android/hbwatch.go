//go:build android

package android

import "github.com/netbirdio/netbird/client/hbwatch"

// CheckHeartbeatsNow asks the heartbeat stale check to look at every connected
// service after a short grace. The app calls it when the screen turns on and
// when a network becomes available again. It is a no-op when the check is
// disabled, before the engine runs and after it stops.
func CheckHeartbeatsNow() {
	hbwatch.CheckNow()
}

// DeviceSleeping tells the heartbeat watcher that the device went to sleep.
// The app calls it when the screen turns off. While the device sleeps and the
// tunnel is idle, Management reconnects wait for a heartbeat or a wake.
func DeviceSleeping() {
	hbwatch.SetDeviceAsleep(true)
}

// DeviceAwake tells the heartbeat watcher that the device woke up. The app
// calls it when the screen turns on.
func DeviceAwake() {
	hbwatch.SetDeviceAsleep(false)
}
