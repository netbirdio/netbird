//go:build !linux || (linux && 386)

package main

func (t *Tray) startTrayTheme() {
	// No-op off Linux: macOS template icons and Windows colored PNGs need no
	// colour-scheme probe. panelDark stays nil; panelIsDark uses its default.
}
