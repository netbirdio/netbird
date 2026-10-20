//go:build linux && !(linux && 386)

package main

// Sources: the freedesktop Settings portal's SettingChanged signal, and on KDE
// the kdeglobals and plasmarc files (a pinned Plasma style fixes the panel's
// appearance without touching the portal's color-scheme — see readDarkMode).
// The dark/light decision lives in tray_theme_linux.go; this file owns the
// session-bus connection and subscriptions.

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

// themeWatcher owns a private session-bus connection so its signal subscription
// is isolated from the SNI watcher's.
type themeWatcher struct {
	conn     *dbus.Conn
	onChange func()

	mu       sync.Mutex
	darkMode bool
}

// startThemeWatcher returns nil if the session bus is unavailable; callers treat
// a nil watcher as "no preference", keeping the default-dark icon.
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

	// The portal's signal says nothing about a pinned Plasma style.
	if isKDE() {
		w.watchKdeConfig()
	}

	log.Infof("tray theme: panel dark mode = %v", w.IsDark())
	return w
}

// IsDark reports true for a nil watcher, so the icon defaults to the white
// silhouette suiting the common dark Linux panel.
func (w *themeWatcher) IsDark() bool {
	if w == nil {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.darkMode
}

// readDarkMode resolves whether the panel the tray icon sits on is dark.
//
// KDE goes first because a pinned Plasma style decides the panel on its own,
// independently of the application colour scheme the portal reports; with no
// style pinned that check defers to KDE's own colour files. Off KDE the
// color-scheme portal is the source; on "no preference" (0) or when unavailable
// we fall back to GTK_THEME (":dark" suffix ⇒ dark), then default to dark.
func (w *themeWatcher) readDarkMode() bool {
	if dark, ok := kdePanelIsDark(); ok {
		return dark
	}
	switch w.readColorScheme() {
	case colorSchemePreferDark:
		return true
	case colorSchemePreferLight:
		return false
	default:
		return gtkThemeIsDark()
	}
}

// readColorScheme returns the raw freedesktop color-scheme value, or
// colorSchemeNoPreference when the portal can't be reached.
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

		// Re-resolve via readDarkMode, not the signal value: under KDE a pinned
		// Plasma style overrides it, so the signal value would be wrong.
		w.update()
	}
}

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

// watchKdeConfig repaints on writes to either KDE file that decides the panel
// appearance. It watches their parent directory, not the files: KDE rewrites
// them atomically (write-temp + rename), which would drop an inotify watch on
// the original inode. Filtering by name re-arms implicitly.
func (w *themeWatcher) watchKdeConfig() {
	path := kdeglobalsPath()
	if path == "" {
		return
	}
	dir := filepath.Dir(path)

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		log.Debugf("tray theme: KDE config watcher unavailable, theme is static: %v", err)
		return
	}
	if err := fw.Add(dir); err != nil {
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
				switch filepath.Base(event.Name) {
				case kdeglobalsFile, plasmarcFile:
				default:
					continue
				}
				// Remove counts: deleting plasmarc unpins the Plasma style, which
				// hands the decision back to the colour scheme and can flip it.
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
					continue
				}
				w.update()
			case err, ok := <-fw.Errors:
				if !ok {
					return
				}
				log.Debugf("tray theme: KDE config watch error: %v", err)
			}
		}
	}()
}

// variantToColorScheme unwraps the color-scheme variant; the portal nests it one level.
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
