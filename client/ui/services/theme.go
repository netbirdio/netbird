//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"sync"
	"sync/atomic"

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
	// started gates the main-thread dispatch in apply: Run installs the platform
	// layer InvokeAsync needs, and the store subscription can fire before that.
	started atomic.Bool
}

// NewTheme wires the store subscription and OS theme-change listener. Call
// before any window is created so creation-time colours are already themed.
func NewTheme(app *application.App, store *preferences.Store) *Theme {
	t := &Theme{app: app, store: store}
	pref := store.Get().Theme
	setAppearance(pref, resolveDark(pref, app.Env.IsDarkMode()))

	// Window creation resolves through this rather than the seed above, which
	// is wrong until Run installs the platform layer: Env.IsDarkMode reports
	// light before that, so a "system" launch on a dark OS would build the
	// first window light. The ApplicationStarted apply below cannot be relied
	// on to land first because Wails runs each listener in its own goroutine.
	// One store read backs both fields, so the snapshot is always self-consistent.
	setAppearanceResolver(func() Appearance {
		p := t.store.Get().Theme
		return Appearance{Pref: p, Dark: resolveDark(p, t.app.Env.IsDarkMode())}
	})

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

	// Startup is split in two because Wails runs every application-event
	// listener in its own goroutine, so a listener cannot be ordered against the
	// one that opens the first-launch window. Hooks can: they run sequentially,
	// in registration order, and all of them before any listener is spawned.
	//
	// The app-wide GTK theme goes in the hook because it is the part a window
	// must not be created without. On Linux it draws the decorations and
	// application.LinuxWindow carries no theme of its own, so a window built
	// before it lands shows OS-coloured decorations until it does. It is applied
	// synchronously for the same reason -- returning from the hook has to mean
	// the theme is live. This relies on the listener below existing: Wails skips
	// an event's hooks entirely when it has no listeners.
	app.Event.RegisterApplicationEventHook(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		t.started.Store(true)
		t.syncAppAppearance()
	})

	// The rest of the startup apply. Env.IsDarkMode is a stub until the platform
	// layer is up, so re-resolve once the app has started or a "system" launch on
	// a light OS stays seeded dark.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		t.apply()
	})

	return t
}

// syncAppAppearance applies the app-wide appearance and waits for the UI thread
// to have done it. Use it where a window is about to be created and must not be
// built against the OS appearance: apply dispatches its own native work
// asynchronously, so on Linux the GTK theme behind the decorations can otherwise
// land after the window exists.
//
// No-op before the app has started, where InvokeSync has no platform layer to
// dispatch to. Reads the appearance under mu like apply, so the two cannot
// interleave into a torn update.
func (t *Theme) syncAppAppearance() {
	if !t.started.Load() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	pref := t.store.Get().Theme
	dark := resolveDark(pref, t.app.Env.IsDarkMode())
	setAppearance(pref, dark)
	application.InvokeSync(func() { setAppAppearance(dark) })
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
//
// The OS is read exactly once per update and the resolved value is passed on to
// the background and the native chrome, so those cannot land on either side of
// an OS flip that happens mid-apply. The event carries the raw system reading,
// not the resolved one, because the frontend resolves "system" itself.
func (t *Theme) apply() {
	t.mu.Lock()
	defer t.mu.Unlock()

	pref := t.store.Get().Theme
	systemDark := t.app.Env.IsDarkMode()
	dark := resolveDark(pref, systemDark)
	setAppearance(pref, dark)
	t.app.Event.Emit(EventSystemThemeChanged, SystemTheme{Dark: systemDark})

	// Before Run there is no platform layer for InvokeAsync to dispatch to.
	// Windows created later read the globals set above.
	if !t.started.Load() {
		return
	}

	colour := windowBackgroundColour(dark)
	// Re-tint on the UI thread and resolve each native handle there. Window
	// teardown (markAsDestroyed then impl.close) runs as UI-thread work too, so
	// a window closed meanwhile is either gone from GetAll or yields a nil
	// handle -- never a freed handle the OS may already have reused.
	application.InvokeAsync(func() {
		// App-wide first, and unconditionally: on Linux this is the GTK theme
		// that draws the decorations, and it must be set even with no window
		// open because later windows inherit it instead of carrying it.
		setAppAppearance(dark)
		for _, w := range t.app.Window.GetAll() {
			if w == nil {
				continue
			}
			w.SetBackgroundColour(colour)
			setWindowAppearance(w.NativeWindow(), pref, dark)
		}
	})
}
