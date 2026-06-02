//go:build linux && !(linux && 386)

package main

// Linux panel-theme detection for the monochrome tray icons.
//
// Wails v3's Linux SNI backend does not honour SetDarkModeIcon — its
// setDarkModeIcon just calls setIcon, so the last write wins regardless of
// panel theme (see pkg/application/systemtray_linux.go). The SNI spec itself
// also carries no reliable "panel is dark/light" hint for clients. So we
// detect the desktop's colour scheme ourselves and pick the black or white
// silhouette in iconForState.
//
// This file holds the (stateless) dark/light decision helpers; the live
// watcher that seeds and repaints on change lives in
// tray_theme_watcher_linux.go.
//
// color-scheme values (per the freedesktop appearance spec):
//   0 = no preference, 1 = prefer dark, 2 = prefer light.

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// startTrayTheme wires the Linux panel-theme watcher into the tray: it seeds
// t.panelDark from the freedesktop Settings portal and repaints the icon on
// every live colour-scheme flip. Called from NewTray before the first
// applyIcon so the initial paint already uses the right silhouette.
func (t *Tray) startTrayTheme() {
	w := startThemeWatcher(func() { t.applyIcon() })
	t.panelDark = w.IsDark
}

// isKDE reports whether the current desktop is KDE Plasma. XDG_CURRENT_DESKTOP
// is a colon-separated list (e.g. "KDE", "ubuntu:KDE"), so we match the token.
func isKDE() bool {
	for _, d := range strings.Split(os.Getenv("XDG_CURRENT_DESKTOP"), ":") {
		if strings.EqualFold(strings.TrimSpace(d), "KDE") {
			return true
		}
	}
	return false
}

// kdeglobalsPath returns the user kdeglobals path ($XDG_CONFIG_HOME/kdeglobals,
// or ~/.config/kdeglobals), the highest-priority file in KDE's config cascade.
// We read only this file rather than replaying the full XDG_CONFIG_DIRS +
// kdedefaults cascade: the user file is where Plasma writes the active scheme,
// and if the Complementary group is absent here we fall back to the portal.
func kdeglobalsPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "kdeglobals")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "kdeglobals")
}

// kdePanelIsDark reports whether the KDE Plasma panel is dark, reading the
// Breeze "Complementary" background — the colour Plasma actually paints the
// panel/system-tray with — from kdeglobals and deciding by its luma. The
// second return is false when this isn't KDE or the colour can't be read, so
// readDarkMode falls through to the portal/GTK path.
func kdePanelIsDark() (dark, ok bool) {
	if !isKDE() {
		return false, false
	}
	path := kdeglobalsPath()
	if path == "" {
		return false, false
	}
	rgb, ok := readKdeComplementaryBackground(path)
	if !ok {
		return false, false
	}
	return isDarkRGB(rgb[0], rgb[1], rgb[2]), true
}

// readKdeComplementaryBackground parses kdeglobals for
// [Colors:Complementary] BackgroundNormal and returns its R,G,B (0-255).
func readKdeComplementaryBackground(path string) (rgb [3]uint8, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		log.Debugf("tray theme: kdeglobals open failed, using portal: %v", err)
		return rgb, false
	}
	defer func() { _ = f.Close() }()

	const group = "[Colors:Complementary]"
	inGroup := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			inGroup = line == group
			continue
		}
		if !inGroup {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "BackgroundNormal" {
			continue
		}
		return parseRGB(strings.TrimSpace(val))
	}
	return rgb, false
}

// parseRGB parses a "r,g,b" triple (KDE's colour format) into bytes.
func parseRGB(s string) (rgb [3]uint8, ok bool) {
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return rgb, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 || n > 255 {
			return rgb, false
		}
		rgb[i] = uint8(n)
	}
	return rgb, true
}

// isDarkRGB reports whether a colour is dark using the Rec. 601 relative luma.
// The 128 midpoint matches the perceptual split between needing a light vs a
// dark foreground.
func isDarkRGB(r, g, b uint8) bool {
	luma := (299*int(r) + 587*int(g) + 114*int(b)) / 1000
	return luma < 128
}

// gtkThemeIsDark inspects the GTK_THEME env var. Empty (no override) is
// treated as dark to match the default-dark fallback used elsewhere.
func gtkThemeIsDark() bool {
	theme := os.Getenv("GTK_THEME")
	if theme == "" {
		return true
	}
	// GTK_THEME is "Name[:variant]"; the dark variant is ":dark".
	return strings.Contains(strings.ToLower(theme), ":dark")
}
