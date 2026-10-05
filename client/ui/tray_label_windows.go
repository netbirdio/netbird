//go:build windows

package main

import "strings"

// menuLabel doubles ampersands so Win32 draws a literal "&" instead of
// consuming it as the menu mnemonic prefix (Wails passes the label unescaped).
func menuLabel(s string) string {
	return strings.ReplaceAll(s, "&", "&&")
}
