//go:build linux && !(linux && 386)

package main

// Linux panel-theme detection for the monochrome tray icons.
//
// Wails v3's Linux SNI backend does not honour SetDarkModeIcon — its
// setDarkModeIcon just calls setIcon, so the last write wins regardless of
// panel theme (see pkg/application/systemtray_linux.go). The SNI spec itself
// also carries no reliable "panel is dark/light" hint for clients. So we
// detect the desktop's colour-scheme preference ourselves via the
// freedesktop Settings portal (org.freedesktop.portal.Settings, the
// org.freedesktop.appearance/color-scheme key) and pick the black or white
// silhouette in iconForState. We also subscribe to the portal's
// SettingChanged signal so a live theme switch repaints the icon.
//
// color-scheme values (per the freedesktop appearance spec):
//   0 = no preference, 1 = prefer dark, 2 = prefer light.

import (
	"os"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const (
	portalBusName    = "org.freedesktop.portal.Desktop"
	portalObjectPath = "/org/freedesktop/portal/desktop"
	portalSettings   = "org.freedesktop.portal.Settings"

	appearanceNamespace = "org.freedesktop.appearance"
	colorSchemeKey      = "color-scheme"

	colorSchemeNoPreference = 0
	colorSchemePreferDark   = 1
	colorSchemePreferLight  = 2
)

// startTrayTheme wires the Linux panel-theme watcher into the tray: it seeds
// t.panelDark from the freedesktop Settings portal and repaints the icon on
// every live colour-scheme flip. Called from NewTray before the first
// applyIcon so the initial paint already uses the right silhouette.
func (t *Tray) startTrayTheme() {
	w := startThemeWatcher(func() { t.applyIcon() })
	t.panelDark = w.IsDark
}

// themeWatcher reads the desktop colour-scheme preference over the session
// bus and invokes onChange whenever it flips. It owns a private session-bus
// connection so its signal subscription is isolated from the SNI watcher's.
type themeWatcher struct {
	conn     *dbus.Conn
	onChange func()

	mu       sync.Mutex
	darkMode bool
}

// startThemeWatcher opens a private session-bus connection, seeds the current
// colour scheme, and subscribes to the portal's SettingChanged signal. It
// returns nil (and logs) if the portal is unavailable — callers treat a nil
// watcher as "no preference", which keeps the default-dark icon choice.
func startThemeWatcher(onChange func()) *themeWatcher {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		log.Debugf("tray theme: session bus unavailable, defaulting to dark icons: %v", err)
		return nil
	}
	if err := conn.Auth(nil); err != nil {
		_ = conn.Close()
		log.Debugf("tray theme: dbus auth failed: %v", err)
		return nil
	}
	if err := conn.Hello(); err != nil {
		_ = conn.Close()
		log.Debugf("tray theme: dbus hello failed: %v", err)
		return nil
	}

	w := &themeWatcher{conn: conn, onChange: onChange}
	w.darkMode = w.readDarkMode()

	if err := w.subscribe(); err != nil {
		log.Debugf("tray theme: SettingChanged subscription failed, theme is static: %v", err)
		// Keep the connection: the seeded darkMode value is still useful.
	}

	log.Infof("tray theme: panel dark mode = %v", w.IsDark())
	return w
}

// IsDark reports the last observed colour-scheme preference. A nil watcher
// (portal unavailable) reports true so the icon defaults to the white
// silhouette, which suits the common dark Linux panel.
func (w *themeWatcher) IsDark() bool {
	if w == nil {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.darkMode
}

// readDarkMode resolves the current dark/light preference. The freedesktop
// color-scheme portal is the primary source; when it is unavailable or
// reports "no preference" (0), we fall back to the GTK_THEME env var (the
// GTK convention appends ":dark" for the dark variant, e.g. "Adwaita:dark").
// If neither yields a signal we default to dark, matching the common dark
// Linux panel.
func (w *themeWatcher) readDarkMode() bool {
	switch w.readColorScheme() {
	case colorSchemePreferDark:
		return true
	case colorSchemePreferLight:
		return false
	default: // colorSchemeNoPreference or portal unavailable
		return gtkThemeIsDark()
	}
}

// readColorScheme returns the raw freedesktop color-scheme value (0 = no
// preference, 1 = prefer dark, 2 = prefer light), or colorSchemeNoPreference
// when the portal can't be reached.
func (w *themeWatcher) readColorScheme() uint32 {
	obj := w.conn.Object(portalBusName, portalObjectPath)
	call := obj.Call(portalSettings+".Read", 0, appearanceNamespace, colorSchemeKey)
	if call.Err != nil {
		log.Debugf("tray theme: portal Read failed, falling back to GTK_THEME: %v", call.Err)
		return colorSchemeNoPreference
	}

	var v dbus.Variant
	if err := call.Store(&v); err != nil {
		log.Debugf("tray theme: portal Read decode failed, falling back to GTK_THEME: %v", err)
		return colorSchemeNoPreference
	}

	return variantToColorScheme(v)
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

// subscribe registers a match rule for the portal's SettingChanged signal and
// spawns a goroutine that re-reads the scheme and fires onChange on each
// relevant change.
func (w *themeWatcher) subscribe() error {
	if err := w.conn.AddMatchSignal(
		dbus.WithMatchObjectPath(portalObjectPath),
		dbus.WithMatchInterface(portalSettings),
		dbus.WithMatchMember("SettingChanged"),
	); err != nil {
		return err
	}

	sigs := make(chan *dbus.Signal, 8)
	w.conn.Signal(sigs)
	go w.loop(sigs)
	return nil
}

// loop consumes SettingChanged signals, filters to the colour-scheme key, and
// repaints the icon when the dark/light preference actually flips.
func (w *themeWatcher) loop(sigs chan *dbus.Signal) {
	for sig := range sigs {
		if sig.Name != portalSettings+".SettingChanged" {
			continue
		}
		// Signal body: (namespace string, key string, value variant).
		if len(sig.Body) < 3 {
			continue
		}
		namespace, _ := sig.Body[0].(string)
		key, _ := sig.Body[1].(string)
		if namespace != appearanceNamespace || key != colorSchemeKey {
			continue
		}
		variant, ok := sig.Body[2].(dbus.Variant)
		if !ok {
			continue
		}

		dark := colorSchemeToDark(variantToColorScheme(variant))
		w.mu.Lock()
		changed := dark != w.darkMode
		w.darkMode = dark
		w.mu.Unlock()

		if changed && w.onChange != nil {
			log.Infof("tray theme: panel dark mode changed to %v", dark)
			w.onChange()
		}
	}
}

// colorSchemeToDark maps a freedesktop color-scheme value to a dark/light
// bool, deferring "no preference" (0) to the GTK_THEME fallback.
func colorSchemeToDark(scheme uint32) bool {
	switch scheme {
	case colorSchemePreferDark:
		return true
	case colorSchemePreferLight:
		return false
	default:
		return gtkThemeIsDark()
	}
}

// variantToColorScheme unwraps the color-scheme variant (the portal nests it
// one level: a variant holding a uint32) into the raw scheme value, returning
// colorSchemeNoPreference for an unexpected payload.
func variantToColorScheme(v dbus.Variant) uint32 {
	inner := v.Value()
	if nested, ok := inner.(dbus.Variant); ok {
		inner = nested.Value()
	}

	switch n := inner.(type) {
	case uint32:
		return n
	case int32:
		return uint32(n)
	case uint8:
		return uint32(n)
	default:
		log.Debugf("tray theme: unexpected color-scheme type %T, assuming no preference", inner)
		return colorSchemeNoPreference
	}
}
