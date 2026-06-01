//go:build !windows && !android && !ios && !freebsd && !js

package main

// menuLabel is the identity on macOS and Linux — both render an ampersand
// literally in tray-menu labels, so no escaping is needed. Windows opts in via
// the sibling tray_label_windows.go file, where a lone "&" would otherwise be
// swallowed as a Win32 mnemonic prefix.
func menuLabel(s string) string { return s }
