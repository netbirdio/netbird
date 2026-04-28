//go:build !windows && !android && !ios && !freebsd && !js

package main

// trayIcon is unused on non-Windows hosts — Linux feeds setIcon a PNG and
// macOS uses SetTemplateIcon. This stub exists so the compiler is happy and
// callers don't need build tags around references.
func trayIcon(_, _ bool, _ string) []byte { return nil }
