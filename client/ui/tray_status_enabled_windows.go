//go:build windows

package main

// statusRowEnabled reports whether the informational status row at the
// top of the tray menu should stay enabled. Always true on Windows:
// the Win32 disabled-state mask desaturates both the row text and the
// HBITMAP painted into the check-mark slot, so a disabled row would
// render the coloured status dot in greyscale and defeat the indicator.
// macOS/Linux disable the row (see tray_status_enabled_other.go) because
// neither platform applies that desaturation and the visual cue that
// the row is informational reads better.
func statusRowEnabled() bool { return true }
