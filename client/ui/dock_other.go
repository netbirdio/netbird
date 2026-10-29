//go:build !darwin && !android && !ios && !freebsd && !js

package main

func initDockObserver() {
	// macOS-only; Linux and Windows taskbar entries already gate on window visibility natively.
}
