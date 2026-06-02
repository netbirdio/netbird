//go:build !linux || (linux && 386)

package main

// startTrayTheme is a no-op off Linux: macOS uses template icons (the OS
// recolours them per menubar appearance) and Windows ships colored PNGs, so
// neither needs the freedesktop colour-scheme probe that the Linux build
// uses to choose between the black and white monochrome silhouettes. Left
// callable so NewTray can invoke it unconditionally; panelDark stays nil and
// panelIsDark returns its default.
func (t *Tray) startTrayTheme() {}
