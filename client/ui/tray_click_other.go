//go:build !darwin && !windows && !android && !ios && !freebsd && !js && (!linux || (linux && 386))

package main

func bindTrayClick(*Tray) {
	// No-op: the remaining platforms covered by this build tag (i386 Linux
	// fallback) have no special left-click handling. Windows wires an explicit
	// handler (tray_click_windows.go); Linux opens the window on left-click
	// (tray_click_linux.go); macOS wires OpenMenu (tray_click_darwin.go). The
	// (linux && 386) arm keeps a no-op fallback for the i386 Linux build, which
	// excludes the cgo XEmbed/SNI files that tray_click_linux.go's build tag
	// matches.
}
