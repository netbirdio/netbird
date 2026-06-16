//go:build !linux || (linux && 386)

package main

func (t *Tray) startTrayTheme() {
	// No-op off Linux: leaves panelDark nil so panelIsDark uses its default.
}
