//go:build !windows && !android && !ios && !freebsd && !js

package main

// bindTrayClick is a no-op on macOS and Linux. On macOS the native
// NSStatusItem auto-shows the menu on left-click; on Linux the
// StatusNotifierItem host paints the menu independently. Binding an
// OnClick→OpenMenu handler is both unnecessary there and actively harmful on
// macOS, where OpenMenu routes through NSStatusItem's blocking [button
// mouseDown:] on the serial main GCD queue and freezes the tray and webview
// until the menu closes (commit c77e5cef8). Windows opts in via the sibling
// tray_click_windows.go file.
func bindTrayClick(*Tray) {}
