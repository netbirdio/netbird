//go:build !windows && !linux && !android && !ios && !freebsd && !js

package main

// statusRowEnabled is false on macOS: disabling the row dims the label (signalling
// non-clickable) while keeping the bitmap opaque, so the coloured dot stays visible.
func statusRowEnabled() bool { return false }
