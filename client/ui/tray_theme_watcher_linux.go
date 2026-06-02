//go:build linux && !(linux && 386)

package main

// themeWatcher: the live half of Linux panel-theme detection. It seeds the
// current dark/light state, then watches for changes from two sources and
// repaints the tray icon when the panel theme flips:
//   - the freedesktop Settings portal's SettingChanged signal (the cross-
//     desktop colour-scheme source), and
//   - on KDE, the user kdeglobals file (the portal's color-scheme doesn't
//     track the panel's Complementary colour — see readDarkMode).
//
// The dark/light decision itself lives in tray_theme_linux.go; this file owns
// the session-bus connection, the signal/file subscriptions, and the repaint.

import (
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
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

	// On KDE the portal's color-scheme signal doesn't track the panel's
	// Complementary colour, so watch kdeglobals directly to repaint on a
	// theme switch.
	if isKDE() {
		w.watchKdeglobals()
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

// readDarkMode resolves whether the desktop panel (where the tray icon sits)
// is dark.
//
// On KDE the freedesktop color-scheme is the *application* window preference,
// not the panel's: Plasma paints its panel and system tray from the Breeze
// "Complementary" colour group, which stays dark even under a Light global
// scheme (kdeglobals [Colors:Window] light vs [Colors:Complementary] dark).
// So a light color-scheme there would wrongly pick the black silhouette,
// which then disappears against the dark panel. We therefore read the actual
// panel background from kdeglobals first under KDE and decide by its luma.
//
// Off KDE (or when kdeglobals can't be read), the freedesktop color-scheme
// portal is the source; when it is unavailable or reports "no preference"
// (0), we fall back to the GTK_THEME env var (the GTK convention appends
// ":dark" for the dark variant, e.g. "Adwaita:dark"). If nothing yields a
// signal we default to dark, matching the common dark Linux panel.
func (w *themeWatcher) readDarkMode() bool {
	if dark, ok := kdePanelIsDark(); ok {
		return dark
	}
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
		if _, ok := sig.Body[2].(dbus.Variant); !ok {
			continue
		}

		// Re-resolve via readDarkMode rather than the signal's value: under
		// KDE the panel colour comes from kdeglobals' Complementary group,
		// not the portal's color-scheme, so the signal value alone would be
		// wrong there. Off KDE this just re-reads the same color-scheme.
		w.update()
	}
}

// update re-resolves the panel dark/light state and repaints the icon if it
// flipped. Shared by the portal-signal loop and the KDE kdeglobals watcher.
func (w *themeWatcher) update() {
	dark := w.readDarkMode()
	w.mu.Lock()
	changed := dark != w.darkMode
	w.darkMode = dark
	w.mu.Unlock()

	if changed && w.onChange != nil {
		log.Infof("tray theme: panel dark mode changed to %v", dark)
		w.onChange()
	}
}

// watchKdeglobals watches the user kdeglobals file for changes and re-resolves
// the panel theme on each write, so a KDE colour-scheme switch repaints the
// icon live. KDE rewrites kdeglobals atomically (write-temp + rename), which
// drops the inotify watch on the original inode, so we watch the parent
// directory and filter to the kdeglobals name, re-arming implicitly.
func (w *themeWatcher) watchKdeglobals() {
	path := kdeglobalsPath()
	if path == "" {
		return
	}
	dir, name := filepath.Split(path)

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		log.Debugf("tray theme: kdeglobals watcher unavailable, theme is static: %v", err)
		return
	}
	if err := fw.Add(filepath.Clean(dir)); err != nil {
		log.Debugf("tray theme: watching %s failed, theme is static: %v", dir, err)
		_ = fw.Close()
		return
	}

	go func() {
		defer func() { _ = fw.Close() }()
		for {
			select {
			case event, ok := <-fw.Events:
				if !ok {
					return
				}
				if filepath.Base(event.Name) != name {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
					continue
				}
				w.update()
			case err, ok := <-fw.Errors:
				if !ok {
					return
				}
				log.Debugf("tray theme: kdeglobals watch error: %v", err)
			}
		}
	}()
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
