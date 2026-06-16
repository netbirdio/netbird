//go:build !darwin && !android && !ios && !freebsd && !js

package main

// macOS-only; no-op on other operating systems
func initDockObserver() {}
