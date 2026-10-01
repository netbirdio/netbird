//go:build !windows && !android && !ios && !freebsd && !js && (!linux || (linux && 386))

package main

func bindTrayClick(*Tray) {
	// No-op: macOS's native NSStatusItem opens the menu on click itself, and
	// binding OnClick→anything blocking there froze the tray historically
	// (see tray_click_windows.go). Windows wires an explicit handler
	// (tray_click_windows.go); Linux opens the window on left-click
	// (tray_click_linux.go). The (linux && 386) arm keeps a no-op fallback for
	// the i386 Linux build, which excludes the cgo XEmbed/SNI files that
	// tray_click_linux.go's build tag matches.
}
