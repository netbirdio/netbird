//go:build !windows && !linux && !android && !ios && !freebsd && !js

package main

// statusRowEnabled reports whether the informational status row at the
// top of the tray menu should stay enabled. False on macOS: it paints
// disabled menu rows at slightly reduced opacity without desaturating
// the leading bitmap, so the coloured status dot stays visible while the
// greyed-out label still signals to the user that the row is
// informational and not clickable. Windows opts in via
// tray_status_enabled_windows.go; Linux via tray_status_enabled_linux.go.
func statusRowEnabled() bool { return false }
