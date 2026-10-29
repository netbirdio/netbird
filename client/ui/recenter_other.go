//go:build (!linux || (linux && 386)) && !freebsd && !android && !ios && !js

package main

// recenterOnShowPredicate returns nil off Linux: macOS and Windows WMs restore
// window position across hide -> show themselves, so Go-side re-centering would
// only fight a window the user moved.
func recenterOnShowPredicate() func() bool {
	return nil
}
