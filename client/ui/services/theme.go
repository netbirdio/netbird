//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/netbirdio/netbird/client/ui/preferences"
)

// EventSystemThemeChanged fires when the OS appearance flips, payload SystemTheme.
// The frontend resolves the "system" preference against it.
const EventSystemThemeChanged = "netbird:system-theme:changed"

// SystemTheme is the EventSystemThemeChanged payload.
type SystemTheme struct {
	Dark bool `json:"dark"`
}

// Theme keeps native window background colours in step with the persisted
// theme preference so no window flashes the wrong surface before the webview
// paints. The frontend applies the matching .dark class via ThemeContext.
type Theme struct {
	app   *application.App
	store *preferences.Store
	// mu serializes apply: concurrent callers could otherwise enqueue a stale
	// pref's native updates after a newer one's.
	mu sync.Mutex
}

// NewTheme wires the store subscription and OS theme-change listener. Call
// before any window is created so creation-time colours are already themed.
func NewTheme(app *application.App, store *preferences.Store) *Theme {
	t := &Theme{app: app, store: store}
	pref := store.Get().Theme
	setThemePref(pref)
	setEffectiveDark(resolveDark(pref, app.Env.IsDarkMode()))

	ch, _ := store.Subscribe()
	go func() {
		var last preferences.Theme
		for p := range ch {
			if p.Theme == last {
				continue
			}
			last = p.Theme
			t.apply()
		}
	}()

	// Re-apply on every OS flip, not just for ThemeSystem: Windows re-evaluates
	// process-level theme state on WM_SETTINGCHANGE, so a forced theme has to be
	// re-asserted or the native chrome drifts to the OS appearance. The event's
	// own IsDarkMode is deliberately unused: Wails runs each application event
	// handler in its own goroutine, so two rapid flips race, and apply re-reads
	// the appearance under mu instead.
	app.Event.OnApplicationEvent(events.Common.ThemeChanged, func(*application.ApplicationEvent) {
		t.apply()
	})

	// Env.IsDarkMode is a stub until the platform layer is up; re-resolve once
	// the app has started so a "system" launch on a light OS isn't seeded dark.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		t.apply()
	})

	return t
}

// SystemDarkMode reports the OS appearance; bound so the frontend can resolve
// the "system" preference from the same source as the native layer.
func (t *Theme) SystemDarkMode(_ context.Context) (bool, error) {
	return t.app.Env.IsDarkMode(), nil
}

// resolveDark maps a preference to an effective appearance against a system
// reading the caller already took.
func resolveDark(pref preferences.Theme, systemDark bool) bool {
	switch pref {
	case preferences.ThemeDark:
		return true
	case preferences.ThemeLight:
		return false
	default:
		return systemDark
	}
}

// apply recomputes the effective appearance, re-tints every live window
// (including the macOS NSWindow appearance so the frame matches the webview)
// and publishes the system appearance the frontend resolves "system" against.
//
// Everything runs under mu and reads the appearance here rather than taking it
// from a caller, so a later apply always carries the fresher state and the
// frontend event is ordered by the same lock as the native assignments. Emit
// only appends to a FIFO mailbox, so holding mu across it cannot block.
func (t *Theme) apply() {
	t.mu.Lock()
	defer t.mu.Unlock()

	pref := t.store.Get().Theme
	systemDark := t.app.Env.IsDarkMode()
	setThemePref(pref)
	setEffectiveDark(resolveDark(pref, systemDark))
	t.app.Event.Emit(EventSystemThemeChanged, SystemTheme{Dark: systemDark})

	colour := CurrentWindowBackgroundColour()
	for _, w := range t.app.Window.GetAll() {
		if w != nil {
			w.SetBackgroundColour(colour)
			setWindowAppearance(w.NativeWindow(), pref)
		}
	}
}
