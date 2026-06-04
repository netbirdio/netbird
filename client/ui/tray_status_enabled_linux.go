//go:build linux

package main

// statusRowEnabled reports whether the informational status row at the
// top of the tray menu should stay enabled. True on Linux: a disabled
// row is painted greyed-out, which makes the connection-status indicator
// at the top of the menu look washed-out. Keeping it enabled lets the
// row (and its coloured status dot) render at full opacity. The row has
// no OnClick handler, so clicking it is still a no-op — enabling only
// affects how it is drawn, not its behaviour. macOS disables the row
// (tray_status_enabled_other.go); Windows enables it for a different
// reason (tray_status_enabled_windows.go).
func statusRowEnabled() bool { return true }
