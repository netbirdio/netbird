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
	// application colour scheme: a style with dark colours under a Light scheme
	// is still a dark panel and still needs the white silhouette.
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

// plasmaStyleIsDark reports the appearance the pinned Plasma style paints the
// panel with, decided by the style's own colours rather than by its name. A
// style that ships a colours file overrides the colour scheme for the shell, and
// nothing requires the name to admit it: breeze-dark happens to, but a style
// named neutrally can carry dark colours just as well (measured on Plasma 6.7.4:
// panel luma 38 while kdeglobals and the portal both reported light).
//
// ok is false when no style is pinned, when the pinned style ships no colours --
// the "default" style, which is exactly the case that follows the colour scheme
// -- and when its colours cannot be read; all three fall through to kdeglobals.
func plasmaStyleIsDark() (dark, ok bool) {
	name, found := readIniValue(plasmarcPath(), "[Theme]", "name")
	if !found || name == "" {
		return false, false
	}
	// The name indexes a directory, so keep it a single harmless path element:
	// it comes from a config file, and "../" in it would point the read anywhere.
	// "." and ".." and "/" survive Base(Clean(name)) unchanged, so reject them
	// by name -- ".." alone would read the colours a level above desktoptheme.
	if name == "." || name == ".." || filepath.IsAbs(name) ||
		name != filepath.Base(filepath.Clean(name)) {
		log.Debugf("tray theme: ignoring plasma style name %q, not a bare directory name", name)
		return false, false
	}
	for _, dir := range plasmaStyleDirs(name) {
		rgb, found := readKdeColour(filepath.Join(dir, "colors"), "[Colors:Window]")
		if !found {
			continue
		}
		return isDarkRGB(rgb[0], rgb[1], rgb[2]), true
	}
	return false, false
}

// plasmaStyleDirs lists where a Plasma style of that name may live, in the order
// Plasma itself resolves them: the user data dir first, so a local style shadows
// a system one of the same name.
func plasmaStyleDirs(name string) []string {
	var dirs []string
	for _, base := range xdgDataDirs() {
		dirs = append(dirs, filepath.Join(base, "plasma", "desktoptheme", name))
	}
	return dirs
}

// xdgDataDirs returns XDG_DATA_HOME (or its default) followed by XDG_DATA_DIRS.
func xdgDataDirs() []string {
	var dirs []string
	if home := os.Getenv("XDG_DATA_HOME"); home != "" {
		dirs = append(dirs, home)
	} else if h, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(h, ".local", "share"))
	}
	system := os.Getenv("XDG_DATA_DIRS")
	if system == "" {
		system = "/usr/local/share:/usr/share"
	}
	for _, dir := range strings.Split(system, ":") {
		if dir != "" {
			dirs = append(dirs, dir)
		}
	}
	return dirs
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
