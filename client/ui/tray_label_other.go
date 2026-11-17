//go:build !windows && !android && !ios && !freebsd && !js

package main

// menuLabel is the identity on macOS/Linux, which render "&" literally;
// Windows escapes it separately (tray_label_windows.go) to dodge the Win32 mnemonic.
func menuLabel(s string) string { return s }
