//go:build !linux || (linux && 386)

package main

// startStatusNotifierWatcher is a no-op on non-Linux platforms (and on
// linux/386, which excludes the cgo XEmbed host).
//
// The in-process org.kde.StatusNotifierWatcher + XEmbed bridge in
// tray_watcher_linux.go only exists to rescue the tray on minimal Linux WMs
// that ship no SNI watcher of their own. macOS and Windows have a native
// system tray that Wails talks to directly, so there is nothing to register
// here — the function body is intentionally empty rather than missing so
// main.go can call startStatusNotifierWatcher() unconditionally across all
// build targets.
func startStatusNotifierWatcher() {
	// Intentionally empty: see the doc comment above.
}
