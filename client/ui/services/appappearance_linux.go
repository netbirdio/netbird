//go:build linux && cgo && !android && !ios

package services

import (
	"os"
	"path/filepath"
	"strings"
)

// setAppAppearance points GTK at the light or dark variant of the current theme
// so the decorations match the webview. Without it a forced Light theme keeps
// dark decorations on a dark desktop, and the reverse.
//
// The theme name is switched, not just gtk-application-prefer-dark-theme:
// desktops such as Ubuntu implement dark mode as a separate theme (Yaru-dark),
// which that flag cannot lighten. The flag is still set for themes that do
// carry both variants under one name. Both are per-process settings, so this
// changes only our own decorations; GTK re-reads the desktop value on a change,
// which is why Theme.apply re-asserts. Must run on the main thread.
//
// GTK styling is app-wide, which is why this is separate from
// setWindowAppearance: it must be applied even when no window exists yet, since
// windows created later inherit it rather than carrying it in their options.
func setAppAppearance(dark bool) {
	target := baseGtkTheme(gtkThemeName())
	if dark {
		if variant, ok := darkGtkVariant(target); ok {
			target = variant
		}
	}
	// An unknown name would leave GTK with no theme at all, so fall back to
	// changing nothing and let the prefer-dark flag do what it can.
	if target != "" && !gtkThemeExists(target) {
		target = ""
	}
	applyGtkTheme(target, dark)
}

// baseGtkTheme strips a dark-variant suffix, so "Yaru-dark" becomes "Yaru".
func baseGtkTheme(name string) string {
	for _, suffix := range []string{"-dark", "-Dark"} {
		if len(name) > len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix) {
			return name[:len(name)-len(suffix)]
		}
	}
	return name
}

// darkGtkVariant reports the installed dark counterpart of a base theme name.
// Themes that carry both variants under one name have none, and rely on
// gtk-application-prefer-dark-theme instead.
func darkGtkVariant(base string) (string, bool) {
	if base == "" {
		return "", false
	}
	for _, suffix := range []string{"-dark", "-Dark"} {
		if candidate := base + suffix; gtkThemeExists(candidate) {
			return candidate, true
		}
	}
	return "", false
}

// gtkThemeExists reports whether a theme of that name is installed, searching
// the same locations GTK does.
func gtkThemeExists(name string) bool {
	if name == "" {
		return false
	}
	for _, dir := range gtkThemeDirs() {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

func gtkThemeDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".themes"))
	}
	if dataHome := os.Getenv("XDG_DATA_HOME"); dataHome != "" {
		dirs = append(dirs, filepath.Join(dataHome, "themes"))
	} else if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".local", "share", "themes"))
	}
	dataDirs := os.Getenv("XDG_DATA_DIRS")
	if dataDirs == "" {
		dataDirs = "/usr/local/share:/usr/share"
	}
	for _, dir := range strings.Split(dataDirs, ":") {
		if dir != "" {
			dirs = append(dirs, filepath.Join(dir, "themes"))
		}
	}
	return dirs
}
