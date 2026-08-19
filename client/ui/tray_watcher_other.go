//go:build (!linux || (linux && 386)) && !freebsd && !android && !ios && !js

package main

// startStatusNotifierWatcher is a no-op stub so main.go can call it across all
// build targets; only minimal Linux WMs need the real watcher (tray_watcher_linux.go).
func startStatusNotifierWatcher() {
	// Intentionally empty: only minimal Linux WMs need the real SNI watcher.
}
