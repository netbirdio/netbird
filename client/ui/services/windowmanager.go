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

// LanguageSubscriber delivers UI preference changes so live window titles can
// follow the active language. Runtime impl is *preferences.Store.
type LanguageSubscriber interface {
	Subscribe() (<-chan preferences.UIPreferences, func())
}

// EventTriggerLogin asks the frontend's startLogin() to begin an SSO flow.
// Emitted by the tray since the tray can't call JS directly.
const EventTriggerLogin = "trigger-login"

// EventBrowserLoginCancel signals that the user dismissed the BrowserLogin
// popup; startLogin() listens for it to tear down the daemon's pending SSO wait.
const EventBrowserLoginCancel = "browser-login:cancel"

// EventSettingsOpen tells the already-mounted settings window which tab to
// land on. Routing through React avoids a SetURL-per-open, which re-mounted
// the provider tree and flashed the SettingsSkeleton.
const EventSettingsOpen = "netbird:settings:open"

// WindowBackgroundColour matches AppLayout's <html> bg-nb-gray-950 (#181A1D).
var WindowBackgroundColour = application.NewRGB(24, 26, 29)

// WindowHeight is shared by the main and Settings windows so the right panel
// inside both ends up the same size.
const WindowHeight = 660

// Wails reads CustomTheme colours as 0x00BBGGRR (RGB byte order reversed).
// Border/title bar match AppRightPanel bg-nb-gray-940 (#1C1E21); title text
// matches text-nb-gray-100 (#E4E7E9).
func u32ptr(v uint32) *uint32 { return &v }

var microsoftWindowsTheme = &application.WindowTheme{
	BorderColour:    u32ptr(0x00211E1C),
	TitleBarColour:  u32ptr(0x00211E1C),
	TitleTextColour: u32ptr(0x00E9E7E4),
}

// MicrosoftWindowsAppearanceOptions is the shared Windows chrome: Mica backdrop
// (no-op pre-22621), dark theme, and custom title bar/border colours so the
// chrome extends the in-window AppRightPanel.
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

// AppleMacOSAppearanceOptions is the shared macOS chrome. The hidden title bar
// inset clears space for the traffic-light buttons; FullScreenNone stops the
// green button offering a full-screen mode that breaks our fixed-size layouts.
func AppleMacOSAppearanceOptions() application.MacWindow {
	return application.MacWindow{
		InvisibleTitleBarHeight: 38,
		Backdrop:                application.MacBackdropNormal,
		TitleBar:                application.MacTitleBarHiddenInset,
		CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
	}
}

// LinuxAppearanceOptions is the shared Linux chrome. WindowIsTranslucent stays
// off so the opaque background paints reliably on compositors that fake
// translucency.
func LinuxAppearanceOptions(icon []byte) application.LinuxWindow {
	return application.LinuxWindow{
		Icon:                icon,
		WindowIsTranslucent: false,
	}
}

// DialogWindowOptions is the baseline for every auxiliary dialog window: fixed
// size, Hidden-on-create (React auto-sizes before first paint), and AlwaysOnTop.
// Callers apply per-dialog overrides before Window.NewWithOptions.
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

// WindowManager owns the auxiliary windows; the main window is created up-front
// in main.go.
//
// Settings is created eagerly (hidden) and hides on close so reopens are
// instant and React keeps its in-window state (tab, scroll, unsaved fields).
// Every other auxiliary window is created on first open and destroyed on
// close, so the macOS dock-reopen handler finds no hidden window to resurrect.
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
	// hiddenForLogin holds windows hidden while the BrowserLogin popup is open
	// (keeps focus on the SSO flow without AlwaysOnTop), restored when it closes.
	hiddenForLogin []application.Window
	mu             sync.Mutex
	// recenterOnShow reports whether Go should re-center on each show. Only true
	// on the minimal-WM / XEmbed-tray path, where the WM neither centers small
	// windows nor restores position across a hide -> show; on full desktops it
	// stays nil so re-centering can't fight a user-moved window. A predicate, not
	// a bool, because the XEmbed tray can appear after the UI starts.
	recenterOnShow func() bool
}

// title resolves a window-title i18n key in the user's current language.
// Falls back to the raw key when translator or prefs are missing.
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

// NewWindowManager wires the manager to the main app. translator and prefs may
// be nil (tests), in which case title() falls back to the raw i18n key.
//
// The Settings window is created here, hidden, so the first OpenSettings paints
// instantly instead of paying webview construction + asset load at click time.
func NewWindowManager(app *application.App, mainWindow *application.WebviewWindow, translator ErrorTranslator, prefs LanguagePreference, linuxIcon []byte) *WindowManager {
	s := &WindowManager{app: app, mainWindow: mainWindow, translator: translator, prefs: prefs, linuxIcon: linuxIcon}
	// If prefs also exposes Subscribe, re-title every live auxiliary window on
	// language flip. Wired here rather than via an exported method so the Wails
	// binding generator doesn't try to expose a LanguageSubscriber param
	// (interface params can't round-trip through JSON).
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
	// Hide on close instead of destroying, preserving in-window React state.
	// Resetting the tab to General on hide means the next OpenSettings("") finds
	// it already there, so showing it is a single Show() — no flash.
	s.settings.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		s.app.Event.Emit(EventSettingsOpen, "general")
		s.settings.Hide()
	})
	return s
}

// retitleAll re-applies the localised title to every alive auxiliary window.
// Snapshots the window pointers under s.mu so a concurrent Open*/Close* can't
// race; SetTitle dispatches to the OS UI thread, so the calls are safe to make
// after releasing the lock.
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

// OpenSettings shows the settings window on tab (empty → General).
//
// The window keeps a single URL (/#/settings) for its lifetime: SetURL per open
// re-loaded the WKWebView, re-mounting the AppLayout provider stack and flashing
// the SettingsSkeleton. Instead React keeps the tab in local state and switches
// it on EventSettingsOpen.
func (s *WindowManager) OpenSettings(tab string) {
	target := tab
	if target == "" {
		target = "general"
	}
	s.app.Event.Emit(EventSettingsOpen, target)
	s.settings.Show()
	s.settings.Focus()
	// Re-center (minimal-WM only): Settings is hidden on close, and a hide ->
	// show round-trip lands it in the corner unless re-centered.
	s.centerWhenReady(s.settings)
}

// OpenBrowserLogin shows the SSO popup window, creating it on first use. uri is
// encoded into the start URL so the React page reads it via useSearchParams.
func (s *WindowManager) OpenBrowserLogin(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.browserLogin == nil {
		startURL := "/#/dialog/browser-login"
		if uri != "" {
			startURL = "/#/dialog/browser-login?uri=" + url.QueryEscape(uri)
		}
		s.hideOtherWindowsLocked("browser-login")
		// Prefer the main window's screen so the popup shows where the user is
		// looking on multi-monitor setups; falls back to OS-default centering.
		var screen *application.Screen
		if s.mainWindow != nil {
			if sc, err := s.mainWindow.GetScreen(); err == nil {
				screen = sc
			}
		}
		opts := DialogWindowOptions("browser-login", s.title("window.title.signIn"), startURL, s.linuxIcon)
		// Not always-on-top: the user moves between the browser tab and the
		// popup; pinning it would obscure the browser when they need it.
		opts.AlwaysOnTop = false
		opts.InitialPosition = application.WindowCentered
		opts.Screen = screen
		s.browserLogin = s.app.Window.NewWithOptions(opts)
		bl := s.browserLogin
		// Red-X close means cancel: emit the event so startLogin() tears down
		// the SSO wait, then let the window destroy naturally.
		bl.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.app.Event.Emit(EventBrowserLoginCancel)
			s.mu.Lock()
			s.browserLogin = nil
			s.restoreHiddenWindowsLocked()
			s.mu.Unlock()
		})
		// First open: the window is Hidden; React auto-sizes and calls Show/Focus
		// once content is measured. centerWhenReady polls for that JS-driven show
		// (minimal-WM only).
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

// hideOtherWindowsLocked hides every visible window except keepName, recording
// them in hiddenForLogin for restoreHiddenWindowsLocked. Caller must hold s.mu.
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

// restoreHiddenWindowsLocked re-shows windows hidden by
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

// BrowserLoginWindow returns the live SSO popup, or nil if no SSO flow is in
// progress. While non-nil it is the app's focal window: tray "Open" and
// dock/taskbar activation hand off to it instead of the main window.
func (s *WindowManager) BrowserLoginWindow() *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.browserLogin
}

// InstallProgressWindow returns the live install-progress window, or nil. Same
// focal-window contract as BrowserLoginWindow; install supersedes every other
// surface, so check this first.
func (s *WindowManager) InstallProgressWindow() *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.installProgress
}

// CloseBrowserLogin destroys the SSO popup. Called from startLogin() when the
// flow completes or cancels programmatically.
func (s *WindowManager) CloseBrowserLogin() {
	s.mu.Lock()
	w := s.browserLogin
	s.browserLogin = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenSessionExpiration shows the countdown warning above all windows on the
// display the cursor is on. seconds seeds the React-side mm:ss countdown.
// Singleton, destroyed on close.
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

func (s *WindowManager) CloseSessionExpiration() {
	s.mu.Lock()
	w := s.sessionExpiration
	s.sessionExpiration = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenInstallProgress shows the install-progress window above all windows. The
// daemon is unreliable mid-install (the installer restarts it), so this window
// owns its own polling loop against Update.GetInstallerResult and treats a
// sustained gRPC failure as success.
//
// All other visible windows are hidden during the install (restored on close)
// so the user can't reach other menus. Singleton, destroyed on close.
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

func (s *WindowManager) CloseInstallProgress() {
	s.mu.Lock()
	w := s.installProgress
	s.installProgress = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenWelcome shows the first-launch onboarding window. The Continue button
// calls Preferences.SetOnboardingCompleted(true) before closing so the flow
// doesn't re-run. Singleton, destroyed on close.
func (s *WindowManager) OpenWelcome() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.welcome == nil {
		opts := DialogWindowOptions("welcome", s.title("window.title.welcome"), "/#/dialog/welcome", s.linuxIcon)
		opts.Width = 420
		// Stays AlwaysOnTop (inherited) so the first-launch flow can't get
		// buried. nil Screen centers on the primary display.
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

func (s *WindowManager) CloseWelcome() {
	s.mu.Lock()
	w := s.welcome
	s.welcome = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenError shows the custom error dialog above all windows. title and message
// are pre-localised by the caller and ride in the start URL (read via
// useSearchParams). A second error while one is open is steered via SetURL so
// it replaces the first instead of stacking. Singleton, destroyed on close.
//
// In-window alternative to a native MessageBox: keeps the frameless chrome and
// avoids the Windows parent-disable race the native path had to detach around.
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

// errorDialogURL builds the error window's hash-route start URL with title and
// message as query params, escaped so newlines and ampersands common in
// formatted daemon errors survive into useSearchParams.
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

func (s *WindowManager) CloseError() {
	s.mu.Lock()
	w := s.errorDialog
	s.errorDialog = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenMain brings the main window forward. The welcome Continue button uses it
// to hand off from onboarding without depending on the tray.
func (s *WindowManager) OpenMain() {
	s.ShowMain()
}

// ShowMain brings the main window forward, centering on each show (see
// centerWhenReady). The single entry point every surface (tray, SIGUSR1,
// welcome handoff) should use so centering applies uniformly.
func (s *WindowManager) ShowMain() {
	if s.mainWindow == nil {
		return
	}
	s.mainWindow.Show()
	s.mainWindow.Focus()
	// Re-center (minimal-WM only; see centerWhenReady). The window is hidden on
	// close, and minimal WMs re-place it top-left across a hide -> show instead
	// of restoring its position.
	s.centerWhenReady(s.mainWindow)
}

// SetRecenterOnShow installs the recenterOnShow predicate (see the field). The
// Linux startup path passes xembedTrayAvailable; macOS/Windows and tests leave
// it unset.
func (s *WindowManager) SetRecenterOnShow(pred func() bool) {
	s.recenterOnShow = pred
}

// getScreenBasedOnCursorPosition returns the display the OS cursor is on,
// falling back to the main-window screen, then nil (OS-default placement).
// On Linux the cursor query uses XQueryPointer, which works on Wayland via
// XWayland.
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

// centerWhenReady centers w once its native window exists, but only where the
// WM won't (recenterOnShow); otherwise it returns immediately so it never fights
// a user-moved window.
//
// An inline Center() after Show() doesn't work on Linux/GTK4: Center() moves via
// raw X11, which silently no-ops while the GdkSurface is nil, and GTK4 realizes
// the surface asynchronously after Show() returns. Deferring via InvokeAsync
// would deadlock (Center hops to the main thread with InvokeSync). So a
// background goroutine retries (Center/Position are main-thread-safe off-thread)
// until a non-zero Position confirms the surface is realized, bounded so a
// window legitimately centered at the origin can't spin forever.
func (s *WindowManager) centerWhenReady(w *application.WebviewWindow) {
	if w == nil || s.recenterOnShow == nil || !s.recenterOnShow() {
		return
	}
	go func() {
		for i := 0; i < 50; i++ { // ~1s budget at 20ms steps
			w.Center()
			if x, y := w.Position(); x != 0 || y != 0 {
				return // surface realized
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
}

// centerOnCursorScreen centers w in the work area of the display the cursor is
// on. Each guard no-ops (nil window, no cursor screen, zero size/work area) so
// headless sessions are safe. On minimal WMs (recenterOnShow) the same
// realize-detection retry loop as centerWhenReady kicks in.
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
