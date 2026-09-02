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

// The two KDE files that decide the panel's appearance. Both live in the user
// config dir, so one directory watch covers them (see watchKdeConfig).
const (
	kdeglobalsFile = "kdeglobals"
	plasmarcFile   = "plasmarc"
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

// kdeConfigPath locates one of KDE's user config files. We read only the user
// file, not the full XDG_CONFIG_DIRS cascade: Plasma writes the active scheme
// and style there, and anything missing falls back to the portal.
func kdeConfigPath(name string) string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, name)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", name)
}

func kdeglobalsPath() string { return kdeConfigPath(kdeglobalsFile) }
func plasmarcPath() string   { return kdeConfigPath(plasmarcFile) }

// kdePanelIsDark reports whether the KDE Plasma panel the tray icon sits on is
// dark. ok is false when this isn't KDE or neither source was conclusive, so the
// caller falls through to the portal/GTK path.
func kdePanelIsDark() (dark, ok bool) {
	if !isKDE() {
		return false, false
	}
	// A pinned Plasma style paints the panel itself, so it outranks the
	// application colour scheme: breeze-dark under a Light scheme is still a
	// dark panel and still needs the white silhouette.
	if dark, ok := plasmaStyleIsDark(); ok {
		return dark, true
	}
	// The default style follows the colour scheme, so decide by the luma of the
	// window background Plasma derives the panel from. Deliberately not
	// Complementary: that group is dark under Breeze *and* BreezeLight
	// (42,46,50 measured on Plasma 6.7.4), so reading it kept the white icon on
	// a light panel, where it is all but invisible.
	rgb, ok := readKdeColour(kdeglobalsPath(), "[Colors:Window]")
	if !ok {
		return false, false
	}
	return isDarkRGB(rgb[0], rgb[1], rgb[2]), true
}

// plasmaStyleIsDark reports the appearance a pinned Plasma style fixes the panel
// to, read from plasmarc's [Theme] name. ok is false when no style is pinned
// (the default, where plasmarc is usually absent altogether) and for any style
// whose name says nothing about its appearance; both follow the colour scheme.
func plasmaStyleIsDark() (dark, ok bool) {
	name, found := readIniValue(plasmarcPath(), "[Theme]", "name")
	if !found {
		return false, false
	}
	name = strings.ToLower(name)
	switch {
	case strings.Contains(name, "dark"):
		return true, true
	case strings.Contains(name, "light"):
		return false, true
	default:
		return false, false
	}
}

// readKdeColour reads group's BackgroundNormal as an R,G,B triple.
func readKdeColour(path, group string) (rgb [3]uint8, ok bool) {
	val, found := readIniValue(path, group, "BackgroundNormal")
	if !found {
		return rgb, false
	}
	return parseRGB(val)
}

// readIniValue returns key's value inside group from a KDE-style INI file.
// group carries its own brackets, e.g. "[Colors:Window]".
func readIniValue(path, group, key string) (value string, ok bool) {
	if path == "" {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		log.Debugf("tray theme: %s open failed, using portal: %v", filepath.Base(path), err)
		return "", false
	}
	defer func() { _ = f.Close() }()

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
		k, v, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(k) != key {
			continue
		}
		return strings.TrimSpace(v), true
	}
	return "", false
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
