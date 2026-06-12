//go:build !android && !ios && !freebsd && !js

package services

import (
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

// LanguageSubscriber delivers UI preference changes (currently only the
// language flip; reusing preferences.UIPreferences keeps the channel
// payload identical to preferences.Store.Subscribe). The runtime
// implementation is *preferences.Store. WindowManager uses this to keep
// the long-lived Settings window title in the active language.
type LanguageSubscriber interface {
	Subscribe() (<-chan preferences.UIPreferences, func())
}

// EventTriggerLogin asks the frontend's startLogin() orchestrator to begin
// an SSO flow. Emitted by the tray (Login menu item, session expired) since
// the tray can't call JS directly.
const EventTriggerLogin = "trigger-login"

// EventBrowserLoginCancel is emitted by the BrowserLogin popup window when
// the user clicks Cancel or closes the window. startLogin() listens for it
// and tears down the daemon's pending SSO wait.
const EventBrowserLoginCancel = "browser-login:cancel"

// EventSettingsOpen tells the (already-mounted, currently-hidden) settings
// window which tab to land on, then drives Window.Show()/Focus() from the
// React side. Routing the open through the React layer avoids the
// SetURL-on-every-open path that re-mounted the entire provider tree and
// flashed the SettingsSkeleton between opens.
const EventSettingsOpen = "netbird:settings:open"

// WindowBackgroundColour is the shared in-window background for every
// NetBird webview (matches the bg-nb-gray utility in the Tailwind config
// at #181A1D / nb-gray-950, used by AppLayout's <html> background).
var WindowBackgroundColour = application.NewRGB(24, 26, 29)

// WindowHeight is the shared frame height for the main window and the
// Settings window so the right panel inside both ends up the same size.
const WindowHeight = 660

// Wails reads CustomTheme colours as 0x00BBGGRR (RGB byte order reversed).
// Border + title bar match AppRightPanel's bg-nb-gray-940 (#1C1E21);
// title text matches text-nb-gray-100 (#E4E7E9). u32ptr exists only
// because WindowTheme fields are *uint32 and Go has no literal address-of.
func u32ptr(v uint32) *uint32 { return &v }

var microsoftWindowsTheme = &application.WindowTheme{
	BorderColour:    u32ptr(0x00211E1C),
	TitleBarColour:  u32ptr(0x00211E1C),
	TitleTextColour: u32ptr(0x00E9E7E4),
}

// MicrosoftWindowsAppearanceOptions is the per-window Microsoft Windows OS
// chrome shared by every NetBird webview window. Mica backdrop (no-op on
// pre-22621), dark theme, custom title bar/border colours so the chrome
// reads as an extension of the in-window AppRightPanel.
func MicrosoftWindowsAppearanceOptions() application.WindowsWindow {
	return application.WindowsWindow{
		BackdropType: application.Mica,
		Theme:        application.Dark,
		CustomTheme: application.ThemeSettings{
			DarkModeActive:    microsoftWindowsTheme,
			DarkModeInactive:  microsoftWindowsTheme,
			LightModeActive:   microsoftWindowsTheme,
			LightModeInactive: microsoftWindowsTheme,
		},
	}
}

// AppleMacOSAppearanceOptions is the per-window macOS chrome shared by
// every NetBird webview window. The hidden title bar inset clears space
// for the traffic-light buttons; the FullScreenNone collection behavior
// keeps the green button from offering a full-screen mode that breaks
// our fixed-size layouts.
func AppleMacOSAppearanceOptions() application.MacWindow {
	return application.MacWindow{
		InvisibleTitleBarHeight: 38,
		Backdrop:                application.MacBackdropNormal,
		TitleBar:                application.MacTitleBarHiddenInset,
		CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
	}
}

// LinuxAppearanceOptions is the per-window Linux chrome shared by every
// NetBird webview window. Icon shows up in the WM task list / minimised
// state; WindowIsTranslucent is left off so the opaque background colour
// paints reliably on compositors that fake translucency badly.
func LinuxAppearanceOptions(icon []byte) application.LinuxWindow {
	return application.LinuxWindow{
		Icon:                icon,
		WindowIsTranslucent: false,
	}
}

// DialogWindowOptions is the baseline for every auxiliary dialog window
// (BrowserLogin, SessionExpiration, InstallProgress).
// All share size (360x320), the no-resize / no-min / no-max chrome,
// Hidden-on-create (so the React side can auto-size before first paint),
// AlwaysOnTop (the dialogs interrupt the user, the SSO popup overrides
// this), and the shared background/Mac/Windows appearance. Callers fill
// in per-dialog overrides (URL params, screen targeting, etc.) on the
// returned value before passing it to Window.NewWithOptions.
func DialogWindowOptions(name, title, url string, linuxIcon []byte) application.WebviewWindowOptions {
	return application.WebviewWindowOptions{
		Name:                name,
		Title:               title,
		Width:               360,
		Height:              320,
		DisableResize:       true,
		AlwaysOnTop:         true,
		Hidden:              true,
		MinimiseButtonState: application.ButtonHidden,
		MaximiseButtonState: application.ButtonHidden,
		CloseButtonState:    application.ButtonEnabled,
		BackgroundColour:    WindowBackgroundColour,
		URL:                 url,
		Mac:                 AppleMacOSAppearanceOptions(),
		Windows:             MicrosoftWindowsAppearanceOptions(),
		Linux:               LinuxAppearanceOptions(linuxIcon),
	}
}

// WindowManager opens auxiliary application windows on demand from the
// frontend. The main window is created up-front in main.go; this service is
// for secondary surfaces (Settings, BrowserLogin, Session*, InstallProgress).
//
// Settings is created eagerly (hidden) at construction and hides — rather
// than destroys — on close, so reopens are instant and the React side keeps
// whatever in-window state the user left behind (selected tab, scroll
// position, unsaved form fields). All other auxiliary windows are created
// on first open and destroyed on close — the Wails-recommended singleton
// pattern (see Multiple Windows docs: "Cleanup on close"). Destroying rather
// than hiding means the macOS dock-reopen handler doesn't find a hidden
// window to resurrect.
type WindowManager struct {
	app               *application.App
	mainWindow        *application.WebviewWindow
	translator        ErrorTranslator
	prefs             LanguagePreference
	linuxIcon         []byte
	settings          *application.WebviewWindow
	browserLogin      *application.WebviewWindow
	sessionExpiration *application.WebviewWindow
	installProgress   *application.WebviewWindow
	welcome           *application.WebviewWindow
	errorDialog       *application.WebviewWindow
	// hiddenForLogin remembers windows that were visible when the
	// BrowserLogin popup opened. They were Hide()n to keep focus on the
	// SSO flow without resorting to AlwaysOnTop, and are restored when
	// the BrowserLogin window closes (success or cancel).
	hiddenForLogin []application.Window
	mu             sync.Mutex
	// recenterOnShow reports whether Go should re-center the Go-shown
	// windows (main, Settings) on each show. Only true in the minimal-WM /
	// in-process XEmbed-tray environment, where the WM neither centers small
	// windows for us nor restores their position across a hide -> show
	// round-trip. On full desktops (GNOME/KDE) the WM handles placement, so
	// re-centering is unnecessary and would fight a window the user moved —
	// there this stays nil and centerWhenReady is a no-op. Set by the Linux
	// startup path via SetRecenterOnShow; nil on macOS/Windows and in tests.
	// A predicate (not a bool) because the XEmbed tray can appear after the
	// UI starts (panel/app login race), so the answer is evaluated per show.
	recenterOnShow func() bool
}

// title resolves a window-title i18n key in the user's current language.
// Falls back to the raw key when the translator or prefs are missing
// (mirrors services.Connection.translateShort) — a deliberate fail-loud
// signal that a key is missing from the bundle.
func (s *WindowManager) title(key string) string {
	if s.translator == nil {
		return key
	}
	lang := i18n.DefaultLanguage
	if s.prefs != nil {
		if pref := s.prefs.Get().Language; pref != "" {
			lang = pref
		}
	}
	return s.translator.Translate(lang, key)
}

// NewWindowManager wires the manager to the main app. `mainWindow` is the
// up-front-created webview the user interacts with from the tray — used to
// pick the BrowserLogin window's display so the sign-in popup follows the
// user onto the screen they're already looking at. `translator` + `prefs`
// resolve the user-facing window titles in the active UI language; both
// may be nil (callers in tests can omit them), in which case title() falls
// back to the raw i18n key.
//
// The Settings window is created here, hidden, so the first OpenSettings
// call paints instantly instead of paying webview construction + asset load
// at click time.
func NewWindowManager(app *application.App, mainWindow *application.WebviewWindow, translator ErrorTranslator, prefs LanguagePreference, linuxIcon []byte) *WindowManager {
	s := &WindowManager{app: app, mainWindow: mainWindow, translator: translator, prefs: prefs, linuxIcon: linuxIcon}
	// If the prefs implementation also exposes Subscribe (the runtime
	// *preferences.Store does), wire up a goroutine that re-titles every
	// live auxiliary window on language flip. Done here — instead of via
	// an exported WatchLanguage method on the service — so the Wails
	// binding generator doesn't try to expose a LanguageSubscriber-taking
	// method to the frontend (interface params can't round-trip through
	// JSON and would emit a generator warning).
	if sub, ok := prefs.(LanguageSubscriber); ok && sub != nil {
		ch, _ := sub.Subscribe()
		go func() {
			var last i18n.LanguageCode
			for p := range ch {
				if p.Language == "" || p.Language == last {
					continue
				}
				last = p.Language
				s.retitleAll()
			}
		}()
	}
	s.settings = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:                "settings",
		Title:               s.title("window.title.settings"),
		Width:               900,
		Height:              WindowHeight,
		Hidden:              true,
		DisableResize:       true,
		MinimiseButtonState: application.ButtonHidden,
		MaximiseButtonState: application.ButtonHidden,
		CloseButtonState:    application.ButtonEnabled,
		BackgroundColour:    WindowBackgroundColour,
		URL:                 "/#/settings",
		Mac:                 AppleMacOSAppearanceOptions(),
		Windows:             MicrosoftWindowsAppearanceOptions(),
		Linux:               LinuxAppearanceOptions(linuxIcon),
	})
	// Hide on close instead of destroying — preserves in-window React state
	// across reopens. Mirrors the main window's close behaviour. Resetting
	// the active tab to General on hide means the *next* OpenSettings("")
	// finds the window already on General, so showing it is a single Show()
	// with nothing to update first — no flash.
	s.settings.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		s.app.Event.Emit(EventSettingsOpen, "general")
		s.settings.Hide()
	})
	return s
}

// retitleAll re-applies the localised title to every currently-alive
// auxiliary window. Reads the window pointers under s.mu so a concurrent
// Open*/Close* can't observe a torn slice. SetTitle itself dispatches to
// the OS UI thread, so calling it from this goroutine is safe.
func (s *WindowManager) retitleAll() {
	s.mu.Lock()
	type pair struct {
		win *application.WebviewWindow
		key string
	}
	wins := []pair{
		{s.settings, "window.title.settings"},
		{s.browserLogin, "window.title.signIn"},
		{s.sessionExpiration, "window.title.sessionExpiration"},
		{s.installProgress, "window.title.updating"},
		{s.welcome, "window.title.welcome"},
		{s.errorDialog, "window.title.error"},
	}
	s.mu.Unlock()
	for _, p := range wins {
		if p.win != nil {
			p.win.SetTitle(s.title(p.key))
		}
	}
}

// OpenSettings asks the (already-mounted, currently-hidden) settings window
// to land on `tab` and bring itself to front. Empty `tab` lands on General.
//
// The window stays at a single URL (`/#/settings`) for its entire lifetime:
// calling SetURL on every open re-loaded the WKWebView, which re-mounted the
// `AppLayout` provider stack and visibly flashed the `SettingsSkeleton` while
// `SettingsContext` re-fetched config. Instead, the React side keeps tab in
// local state and listens for `EventSettingsOpen` to switch it. The close
// hook (above) already resets state to "general", so the common-case
// reopen-on-gear path has nothing to update — Show is a no-op repaint.
func (s *WindowManager) OpenSettings(tab string) {
	target := tab
	if target == "" {
		target = "general"
	}
	s.app.Event.Emit(EventSettingsOpen, target)
	s.settings.Show()
	s.settings.Focus()
	// Re-center on every open (minimal-WM only): like the main window,
	// Settings is hidden (not destroyed) on close, and a hide -> show
	// round-trip lands it back in the corner there unless re-centered.
	s.centerWhenReady(s.settings)
}

// OpenBrowserLogin shows the SSO popup window, creating it on first use (and
// after the user has closed a previous instance). The URI is encoded into
// the window's start URL so the React page reads it via useSearchParams.
func (s *WindowManager) OpenBrowserLogin(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.browserLogin == nil {
		startURL := "/#/dialog/browser-login"
		if uri != "" {
			startURL = "/#/dialog/browser-login?uri=" + url.QueryEscape(uri)
		}
		s.hideOtherWindowsLocked("browser-login")
		// Prefer the screen the main window is on so the sign-in popup
		// shows up where the user is already looking on multi-monitor
		// setups. Falls back to OS-default centering if the main window
		// has no resolvable screen yet.
		var screen *application.Screen
		if s.mainWindow != nil {
			if sc, err := s.mainWindow.GetScreen(); err == nil {
				screen = sc
			}
		}
		opts := DialogWindowOptions("browser-login", s.title("window.title.signIn"), startURL, s.linuxIcon)
		// SSO popup deliberately is NOT always-on-top — the user moves
		// between the browser tab and our popup; pinning it would obscure
		// the browser at the moment they need to interact with it.
		opts.AlwaysOnTop = false
		// WindowCentered + Screen centers on the chosen display's
		// WorkArea (see WebviewWindowOptions.Screen docs) so the popup
		// follows the user onto the screen they're already looking at.
		opts.InitialPosition = application.WindowCentered
		opts.Screen = screen
		s.browserLogin = s.app.Window.NewWithOptions(opts)
		bl := s.browserLogin
		// User-initiated close (red X) means cancel. Emit the event so
		// startLogin() can tear the SSO wait down, then let the window
		// destroy naturally — no hide trickery.
		bl.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.app.Event.Emit(EventBrowserLoginCancel)
			s.mu.Lock()
			s.browserLogin = nil
			s.restoreHiddenWindowsLocked()
			s.mu.Unlock()
		})
		// First open: window is Hidden, the React side auto-sizes via
		// useAutoSizeWindow and calls Window.Show/Focus once content is
		// measured. Returning here avoids the snap from placeholder to
		// measured height. centerWhenReady polls for that JS-driven show,
		// so it centers (minimal-WM only) whoever ends up calling Show.
		s.centerWhenReady(s.browserLogin)
		return
	}
	if uri != "" {
		s.browserLogin.SetURL("/#/dialog/browser-login?uri=" + url.QueryEscape(uri))
	}
	s.browserLogin.Show()
	s.browserLogin.Focus()
	s.centerWhenReady(s.browserLogin)
}

// hideOtherWindowsLocked hides every currently visible window except the one
// named `keepName` and remembers them in hiddenForLogin so they can be
// restored when the BrowserLogin flow ends. Caller must hold s.mu.
func (s *WindowManager) hideOtherWindowsLocked(keepName string) {
	for _, w := range s.app.Window.GetAll() {
		if w == nil || w.Name() == keepName {
			continue
		}
		if !w.IsVisible() {
			continue
		}
		w.Hide()
		s.hiddenForLogin = append(s.hiddenForLogin, w)
	}
}

// restoreHiddenWindowsLocked re-shows every window that was hidden by
// hideOtherWindowsLocked. Caller must hold s.mu.
func (s *WindowManager) restoreHiddenWindowsLocked() {
	for _, w := range s.hiddenForLogin {
		if w == nil {
			continue
		}
		w.Show()
	}
	s.hiddenForLogin = nil
}

// BrowserLoginWindow returns the live SSO popup window, or nil if no SSO
// flow is in progress. While it is non-nil it should be treated as the
// app's focal window — tray "Open" and dock/taskbar activation hand off
// to it instead of the (currently hidden) main window.
func (s *WindowManager) BrowserLoginWindow() *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.browserLogin
}

// InstallProgressWindow returns the live install-progress window, or nil
// if no install is in progress. Same contract as BrowserLoginWindow: while
// it is non-nil it is the app's focal window — tray "Open" and dock /
// taskbar activation route to it instead of the (currently hidden) main
// window. Install supersedes every other surface, so callers should check
// this before BrowserLoginWindow.
func (s *WindowManager) InstallProgressWindow() *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.installProgress
}

// CloseBrowserLogin destroys the SSO popup window if it exists. Called from
// startLogin() when the flow completes or cancels programmatically.
func (s *WindowManager) CloseBrowserLogin() {
	s.mu.Lock()
	w := s.browserLogin
	s.browserLogin = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenSessionExpiration shows the countdown warning above all other
// windows on the display the cursor is currently on. `seconds` seeds the
// mm:ss countdown rendered React-side. Singleton, destroyed on close.
func (s *WindowManager) OpenSessionExpiration(seconds int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	startURL := "/#/dialog/session-expiration?seconds=" + strconv.Itoa(seconds)
	if s.sessionExpiration == nil {
		opts := DialogWindowOptions("session-expiration", s.title("window.title.sessionExpiration"), startURL, s.linuxIcon)
		opts.Screen = s.getScreenBasedOnCursorPosition()
		opts.InitialPosition = application.WindowCentered
		s.sessionExpiration = s.app.Window.NewWithOptions(opts)
		s.sessionExpiration.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.sessionExpiration = nil
			s.mu.Unlock()
		})
		s.centerOnCursorScreen(s.sessionExpiration)
		return
	}
	s.sessionExpiration.SetURL(startURL)
	s.centerOnCursorScreen(s.sessionExpiration)
	s.sessionExpiration.Show()
	s.sessionExpiration.Focus()
}

// CloseSessionExpiration destroys the countdown warning window if open.
func (s *WindowManager) CloseSessionExpiration() {
	s.mu.Lock()
	w := s.sessionExpiration
	s.sessionExpiration = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenInstallProgress shows the install-progress window above all other
// application windows for the duration of the auto-update install. The
// daemon is unreliable mid-install (it gets restarted by the installer),
// so this window owns its own polling loop against Update.GetInstallerResult
// and treats a sustained gRPC failure as success.
//
// All other visible windows are hidden while the install runs — the ticket
// requires that the user can't reach other menus during install — and are
// restored when the window closes (cancel, error dismissal, success-quit
// race). Singleton, destroyed on close. Created Hidden so the React side
// can auto-size before paint.
func (s *WindowManager) OpenInstallProgress(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	startURL := "/#/dialog/install-progress"
	if version != "" {
		startURL = "/#/dialog/install-progress?version=" + url.QueryEscape(version)
	}
	if s.installProgress == nil {
		s.hideOtherWindowsLocked("install-progress")
		s.installProgress = s.app.Window.NewWithOptions(
			DialogWindowOptions("install-progress", s.title("window.title.updating"), startURL, s.linuxIcon),
		)
		s.installProgress.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.installProgress = nil
			s.restoreHiddenWindowsLocked()
			s.mu.Unlock()
		})
		s.centerWhenReady(s.installProgress)
		return
	}
	s.installProgress.SetURL(startURL)
	s.installProgress.Show()
	s.installProgress.Focus()
	s.centerWhenReady(s.installProgress)
}

// CloseInstallProgress destroys the install-progress window if open.
func (s *WindowManager) CloseInstallProgress() {
	s.mu.Lock()
	w := s.installProgress
	s.installProgress = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenWelcome shows the first-launch onboarding window. The React side
// auto-sizes the window height to its content; the Continue button calls
// Preferences.SetOnboardingCompleted(true) before closing so the flow
// doesn't re-run. Singleton, destroyed on close. Created Hidden so the
// React side can auto-size before paint.
func (s *WindowManager) OpenWelcome() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.welcome == nil {
		opts := DialogWindowOptions("welcome", s.title("window.title.welcome"), "/#/dialog/welcome", s.linuxIcon)
		opts.Width = 420
		// Onboarding stays AlwaysOnTop (inherited from DialogWindowOptions)
		// so the user can't accidentally bury the first-launch flow behind
		// another window and lose track of how to finish setup.
		// Land in the middle of the user's primary display — the welcome
		// flow is identity-defining and shouldn't read as an incidental
		// dialog floating in a corner. WindowCentered + nil Screen
		// resolves against the primary display (see WebviewWindowOptions).
		opts.InitialPosition = application.WindowCentered
		s.welcome = s.app.Window.NewWithOptions(opts)
		w := s.welcome
		w.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.welcome = nil
			s.mu.Unlock()
		})
		s.centerWhenReady(s.welcome)
		return
	}
	s.welcome.Show()
	s.welcome.Focus()
	s.centerWhenReady(s.welcome)
}

// CloseWelcome destroys the welcome window if open.
func (s *WindowManager) CloseWelcome() {
	s.mu.Lock()
	w := s.welcome
	s.welcome = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenError shows a custom error dialog window above all other application
// windows. The window's chrome title is always the generic localised "Error";
// `title` is the error's name (e.g. a login failure passes the translated
// "Login Failed") and is rendered as the dialog heading in the body, while
// `message` is the body text below it. The caller is responsible for localising
// both. title + message are carried in the window's start URL so the page reads
// them via useSearchParams; if the window is already open it is steered to the
// new content via SetURL so a second error replaces the first instead of
// stacking another window. Singleton — destroyed on close. Created Hidden so
// the React side can auto-size to the (variable-length) message before paint.
//
// This is the in-window alternative to the native errorDialog wrapper: it
// keeps the frameless NetBird chrome and survives the Windows-MessageBox
// parent-disable race that the native path has to detach around.
func (s *WindowManager) OpenError(title, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	startURL := errorDialogURL(title, message)
	if s.errorDialog == nil {
		s.errorDialog = s.app.Window.NewWithOptions(
			DialogWindowOptions("error", s.title("window.title.error"), startURL, s.linuxIcon),
		)
		s.errorDialog.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.errorDialog = nil
			s.mu.Unlock()
		})
		s.centerWhenReady(s.errorDialog)
		return
	}
	s.errorDialog.SetURL(startURL)
	s.errorDialog.Show()
	s.errorDialog.Focus()
	s.centerWhenReady(s.errorDialog)
}

// errorDialogURL builds the hash-route start URL for the error window with the
// title (rendered as the body heading) and message carried as query params.
// Both are query-escaped so newlines, ampersands, and other characters common
// in formatted daemon errors survive the round-trip into useSearchParams.
func errorDialogURL(title, message string) string {
	q := url.Values{}
	if title != "" {
		q.Set("title", title)
	}
	if message != "" {
		q.Set("message", message)
	}
	startURL := "/#/dialog/error"
	if enc := q.Encode(); enc != "" {
		startURL += "?" + enc
	}
	return startURL
}

// CloseError destroys the error dialog window if open.
func (s *WindowManager) CloseError() {
	s.mu.Lock()
	w := s.errorDialog
	s.errorDialog = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenMain brings the main window forward. Used by the welcome Continue
// button to hand off from onboarding to the regular UI without depending
// on the tray.
func (s *WindowManager) OpenMain() {
	s.ShowMain()
}

// ShowMain brings the main window forward, centering it on each show (see
// centerWhenReady). The single entry point every surface — tray, SIGUSR1,
// welcome handoff — should use so the centering fix applies uniformly.
func (s *WindowManager) ShowMain() {
	if s.mainWindow == nil {
		return
	}
	s.mainWindow.Show()
	s.mainWindow.Focus()
	// Re-center on every show (minimal-WM only — see centerWhenReady). The
	// window is hidden (not destroyed) on close, and on a hide -> show
	// round-trip minimal WMs (the XEmbed tray path) re-place it in the
	// top-left corner rather than restoring its prior position, so
	// re-opening from the tray lands it in the corner again otherwise.
	s.centerWhenReady(s.mainWindow)
}

// SetRecenterOnShow installs the predicate that gates Go-side re-centering of
// the main and Settings windows (see the recenterOnShow field). The Linux
// startup path passes xembedTrayAvailable so re-centering happens only in the
// minimal-WM / in-process-XEmbed-tray environment; macOS/Windows and tests
// leave it unset, making centerWhenReady a no-op.
func (s *WindowManager) SetRecenterOnShow(pred func() bool) {
	s.recenterOnShow = pred
}

// getScreenBasedOnCursorPosition returns the display the OS cursor is
// on, falling back through main-window screen → nil (Wails treats nil
// as OS-default placement). Linux uses XQueryPointer via XWayland on
// Wayland sessions, which ships by default on the supported distros.
func (s *WindowManager) getScreenBasedOnCursorPosition() *application.Screen {
	if s.app == nil || s.app.Screen == nil {
		return nil
	}
	if p, ok := getCursorPosition(s.app); ok {
		if sc := s.app.Screen.ScreenNearestDipPoint(p); sc != nil {
			return sc
		}
	}
	if s.mainWindow != nil {
		if sc, err := s.mainWindow.GetScreen(); err == nil {
			return sc
		}
	}
	return nil
}

// centerWhenReady centers w once its native window actually exists — but only
// in environments where the WM won't do it for us (recenterOnShow). On full
// desktops the WM centers small windows and restores position across hide ->
// show, so this returns immediately and never fights a user-moved window.
//
// Why it can't be a simple inline Center() after Show(): on Linux/GTK4 (Wails'
// linux_cgo backend) Center() moves the window via raw X11 (window_move_x11),
// which silently no-ops while the GdkSurface is still nil — and GTK4 realizes
// the surface asynchronously on the main loop, *after* Show() returns. So an
// immediate Center() races realization and lands in the top-left corner; the
// minimal WMs this targets don't re-center for us, so it sticks.
//
// It also can't be deferred via InvokeAsync(w.Center): Center() itself hops to
// the main thread with InvokeSync, so running it *on* the main thread would
// deadlock. So we drive it from a background goroutine (Center() and Position()
// are main-thread-safe off-thread for exactly that reason) and retry until the
// move actually takes effect, which is the unambiguous signal that the surface
// now exists: position() goes through X11 (window_get_position_x11) and reports
// (0,0) while the surface is nil — so a non-zero post-Center position means the
// centering landed. Bounded so a window that legitimately centers at the origin
// (e.g. fills the monitor) can't spin forever.
func (s *WindowManager) centerWhenReady(w *application.WebviewWindow) {
	if w == nil || s.recenterOnShow == nil || !s.recenterOnShow() {
		return
	}
	go func() {
		for i := 0; i < 50; i++ { // ~1s budget at 20ms steps
			w.Center()
			if x, y := w.Position(); x != 0 || y != 0 {
				return // move took effect -> surface is realized
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
}

// centerOnCursorScreen centers w in the work area of the display the
// cursor is on. Each guard is a no-op (nil window, no cursor screen,
// zero size, zero work area) so a headless / no-monitor session is safe.
// On minimal WMs (recenterOnShow → Fluxbox/XEmbed) the same retry loop
// centerWhenReady uses kicks in: Linux SetPosition silently no-ops while
// the GdkSurface is nil, and a non-zero post-move Position is the
// signal that it landed.
func (s *WindowManager) centerOnCursorScreen(w *application.WebviewWindow) {
	if w == nil {
		return
	}
	place := func() {
		screen := s.getScreenBasedOnCursorPosition()
		if screen == nil {
			return
		}
		width, height := w.Size()
		if width <= 0 || height <= 0 {
			return
		}
		wa := screen.WorkArea
		if wa.Width <= 0 || wa.Height <= 0 {
			return
		}
		w.SetPosition(wa.X+(wa.Width-width)/2, wa.Y+(wa.Height-height)/2)
	}
	place()
	if s.recenterOnShow == nil || !s.recenterOnShow() {
		return
	}
	go func() {
		for i := 0; i < 50; i++ {
			place()
			if x, y := w.Position(); x != 0 || y != 0 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
}
