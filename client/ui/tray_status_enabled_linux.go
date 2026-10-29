//go:build linux

package main

// statusRowEnabled keeps the top status row enabled on Linux: a disabled row
// paints greyed-out, washing out the status dot. The row has no OnClick, so
// enabling only affects drawing.
func statusRowEnabled() bool { return true }
