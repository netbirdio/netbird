//go:build !windows && !linux && !android && !ios && !freebsd && !js

package main

// bindTrayClick is a no-op on macOS. The native NSStatusItem auto-shows the
// menu on left-click, so binding an OnClick→OpenMenu handler is both
// unnecessary and actively harmful: OpenMenu routes through NSStatusItem's
// blocking [button mouseDown:] on the serial main GCD queue and freezes the
// tray and webview until the menu closes (commit c77e5cef8). Windows opts in
// via tray_click_windows.go; Linux via tray_click_linux.go.
func bindTrayClick(*Tray) {}
