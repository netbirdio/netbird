//go:build !windows && !android && !ios && !freebsd && !js

package main

// statusRowEnabled reports whether the informational status row at the
// top of the tray menu should stay enabled. False on macOS and Linux:
// both platforms paint disabled menu rows at slightly reduced opacity
// without desaturating the leading bitmap, so the coloured status dot
// stays visible while the greyed-out label still signals to the user
// that the row is informational and not clickable. Windows opts in via
// the sibling tray_status_enabled_windows.go file.
func statusRowEnabled() bool { return false }
