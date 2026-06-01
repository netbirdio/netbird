//go:build windows

package main

import "strings"

// menuLabel escapes a tray-menu label for Win32. A single ampersand in an
// MFT_STRING menu item is consumed as the mnemonic (accelerator) prefix and
// never painted — so "Help & Support" renders as "Help  Support". Doubling it
// to "&&" tells Win32 to draw a literal ampersand. Wails v3 passes the label
// straight to InsertMenuItem without escaping (see menuitem_windows.go), so we
// do it here. macOS/Linux render "&" literally and use the identity helper in
// the sibling tray_label_other.go.
func menuLabel(s string) string {
	return strings.ReplaceAll(s, "&", "&&")
}
