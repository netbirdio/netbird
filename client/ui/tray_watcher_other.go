//go:build !linux || (linux && 386)

package main

// startStatusNotifierWatcher is a no-op on non-Linux platforms.
func startStatusNotifierWatcher() {}
