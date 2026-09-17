//go:build windows

package main

// statusRowEnabled is always true on Windows: the Win32 disabled-state mask
// desaturates the row's HBITMAP, which would grey out the coloured status dot.
func statusRowEnabled() bool { return true }
