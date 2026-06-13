//go:build linux && !(linux && 386)

package main

// Wails v3's Linux SNI backend ignores SetDarkModeIcon (it just calls setIcon,
// last write wins) and SNI carries no panel dark/light hint, so we detect the
// desktop colour scheme ourselves and pick the silhouette in iconForState.
// The live watcher is in tray_theme_watcher_linux.go.

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// startTrayTheme seeds t.panelDark and repaints on colour-scheme flips. Must
// run before the first applyIcon so the initial paint uses the right silhouette.
func (t *Tray) startTrayTheme() {
	w := startThemeWatcher(func() { t.applyIcon() })
	t.panelDark = w.IsDark
}

// isKDE reports whether the current desktop is KDE Plasma. XDG_CURRENT_DESKTOP
// is a colon-separated list (e.g. "ubuntu:KDE"), so match per token.
func isKDE() bool {
	for _, d := range strings.Split(os.Getenv("XDG_CURRENT_DESKTOP"), ":") {
		if strings.EqualFold(strings.TrimSpace(d), "KDE") {
			return true
		}
	}
	return false
}

// kdeglobalsPath returns the user kdeglobals path. We read only this file, not
// the full XDG_CONFIG_DIRS cascade: Plasma writes the active scheme here, and a
// missing Complementary group falls back to the portal.
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

// kdePanelIsDark reports whether the KDE Plasma panel is dark by the luma of
// its "Complementary" background (the colour Plasma paints the tray with). ok
// is false when this isn't KDE or the colour can't be read, so the caller falls
// through to the portal/GTK path.
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

// parseRGB parses KDE's "r,g,b" colour triple into bytes.
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

// isDarkRGB reports whether a colour is dark via Rec. 601 luma, split at the
// 128 midpoint.
func isDarkRGB(r, g, b uint8) bool {
	luma := (299*int(r) + 587*int(g) + 114*int(b)) / 1000
	return luma < 128
}

// gtkThemeIsDark inspects the GTK_THEME env var. Empty (no override) is treated
// as dark to match the default-dark fallback used elsewhere.
func gtkThemeIsDark() bool {
	theme := os.Getenv("GTK_THEME")
	if theme == "" {
		return true
	}
	// GTK_THEME is "Name[:variant]"; the dark variant is ":dark".
	return strings.Contains(strings.ToLower(theme), ":dark")
}
