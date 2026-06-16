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

// LanguageSubscriber delivers UI preference changes so window titles follow the language.
type LanguageSubscriber interface {
	Subscribe() (<-chan preferences.UIPreferences, func())
}

// EventTriggerLogin asks the frontend's startLogin() to begin an SSO flow.
const EventTriggerLogin = "trigger-login"

// EventBrowserLoginCancel signals the user dismissed the BrowserLogin popup.
const EventBrowserLoginCancel = "browser-login:cancel"

// EventSettingsOpen tells the mounted settings window which tab to show.
const EventSettingsOpen = "netbird:settings:open"

var WindowBackgroundColour = application.NewRGB(24, 26, 29) // bg-nb-gray-950

// WindowHeight is shared by the main and Settings windows.
const WindowHeight = 660

// Wails reads CustomTheme colours as 0x00BBGGRR (RGB byte order reversed).
var microsoftWindowsTheme = &application.WindowTheme{
	BorderColour:    u32ptr(0x00211E1C),
	TitleBarColour:  u32ptr(0x00211E1C),
	TitleTextColour: u32ptr(0x00E9E7E4),
}

// MicrosoftWindowsAppearanceOptions is the shared Windows chrome (Mica + dark + custom title bar).
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

// AppleMacOSAppearanceOptions is the shared macOS chrome; FullScreenNone keeps the fixed-size layout.
func AppleMacOSAppearanceOptions() application.MacWindow {
	return application.MacWindow{
		InvisibleTitleBarHeight: 38,
		Backdrop:                application.MacBackdropNormal,
		TitleBar:                application.MacTitleBarHiddenInset,
		CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
	}
}

// LinuxAppearanceOptions is the shared Linux chrome; opaque so fake-translucency compositors paint it.
func LinuxAppearanceOptions(icon []byte) application.LinuxWindow {
	return application.LinuxWindow{
		Icon:                icon,
		WindowIsTranslucent: false,
	}
}

// DialogWindowOptions is the baseline for every auxiliary dialog window; callers override per-dialog.
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

// WindowManager owns the auxiliary windows (main is created in main.go). Settings is created
// eagerly and hidden on close to keep React state; the rest are created on open, destroyed on
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
	// hiddenForLogin holds windows hidden while the BrowserLogin popup is open, restored on close.
	hiddenForLogin []application.Window
	mu             sync.Mutex
	// recenterOnShow is set only on the minimal-WM/XEmbed path, where the WM neither centers nor
	// restores position; nil on full desktops so re-centering can't fight a user-moved window.
	recenterOnShow func() bool
}

// NewWindowManager wires the manager to the main app; translator/prefs may be nil (tests). The
// Settings window is created here (hidden) so the first OpenSettings is instant.
func NewWindowManager(app *application.App, mainWindow *application.WebviewWindow, translator ErrorTranslator, prefs LanguagePreference, linuxIcon []byte) *WindowManager {
	s := &WindowManager{app: app, mainWindow: mainWindow, translator: translator, prefs: prefs, linuxIcon: linuxIcon}
	// Re-title live windows on language flip. Wired internally so the binding generator
	// doesn't try to expose the interface param.
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
	// Hide (not destroy) on close to keep React state; reset to General for a flash-free reopen.
	s.settings.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		s.app.Event.Emit(EventSettingsOpen, "general")
		s.settings.Hide()
	})
	return s
}

// OpenSettings shows the settings window on tab (empty → General), switching tab via
// EventSettingsOpen rather than SetURL (which would remount the provider tree).
func (s *WindowManager) OpenSettings(tab string) {
	target := tab
	if target == "" {
		target = "general"
	}
	s.app.Event.Emit(EventSettingsOpen, target)
	s.settings.Show()
	s.settings.Focus()
	// Re-center (minimal-WM only; see centerWhenReady).
	s.centerWhenReady(s.settings)
}

// OpenBrowserLogin shows the SSO popup, creating it on first use.
func (s *WindowManager) OpenBrowserLogin(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.browserLogin == nil {
		startURL := "/#/dialog/browser-login"
		if uri != "" {
			startURL = "/#/dialog/browser-login?uri=" + url.QueryEscape(uri)
		}
		s.hideOtherWindowsLocked("browser-login")
		// Prefer the main window's screen (multi-monitor); falls back to OS-default centering.
		var screen *application.Screen
		if s.mainWindow != nil {
			if sc, err := s.mainWindow.GetScreen(); err == nil {
				screen = sc
			}
		}
		opts := DialogWindowOptions("browser-login", s.title("window.title.signIn"), startURL, s.linuxIcon)
		// Not always-on-top: it would obscure the browser tab the user logs in through.
		opts.AlwaysOnTop = false
		opts.InitialPosition = application.WindowCentered
		opts.Screen = screen
		s.browserLogin = s.app.Window.NewWithOptions(opts)
		bl := s.browserLogin
		// Red-X close means cancel: emit the event so startLogin() tears down the SSO wait.
		bl.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.app.Event.Emit(EventBrowserLoginCancel)
			s.mu.Lock()
			s.browserLogin = nil
			s.restoreHiddenWindowsLocked()
			s.mu.Unlock()
		})
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

// BrowserLoginWindow returns the live SSO popup, or nil. While non-nil it is the
// app's focal window: tray "Open" and dock activation hand off to it, not the main window.
func (s *WindowManager) BrowserLoginWindow() *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.browserLogin
}

// InstallProgressWindow returns the live install-progress window, or nil. Same focal-window
// contract as BrowserLoginWindow; install supersedes everything, so check this first.
func (s *WindowManager) InstallProgressWindow() *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.installProgress
}

func (s *WindowManager) CloseBrowserLogin() {
	s.mu.Lock()
	w := s.browserLogin
	s.browserLogin = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenSessionExpiration shows the countdown warning on the cursor's display; seconds seeds
// the countdown. Singleton, destroyed on close.
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

// OpenInstallProgress shows the install-progress window and hides the rest for the duration
// (restored on close). It owns its own result polling since the daemon restarts mid-install.
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

// OpenWelcome shows the first-launch onboarding window. Singleton, destroyed on close.
func (s *WindowManager) OpenWelcome() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.welcome == nil {
		opts := DialogWindowOptions("welcome", s.title("window.title.welcome"), "/#/dialog/welcome", s.linuxIcon)
		opts.Width = 420
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

// OpenError shows the custom error dialog; title/message are pre-localised and ride in the
// start URL. A second error replaces the open one via SetURL. Singleton, destroyed on close.
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

func (s *WindowManager) CloseError() {
	s.mu.Lock()
	w := s.errorDialog
	s.errorDialog = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenMain brings the main window forward; the welcome handoff uses it instead of the tray.
func (s *WindowManager) OpenMain() {
	s.ShowMain()
}

// ShowMain brings the main window forward (re-centering on minimal WMs). The single entry
// point every surface (tray, SIGUSR1, welcome) should use so centering applies uniformly.
func (s *WindowManager) ShowMain() {
	if s.mainWindow == nil {
		return
	}
	s.mainWindow.Show()
	s.mainWindow.Focus()
	// Re-center (minimal-WM only; see centerWhenReady).
	s.centerWhenReady(s.mainWindow)
}

// SetRecenterOnShow installs the recenterOnShow predicate (see the field).
func (s *WindowManager) SetRecenterOnShow(pred func() bool) {
	s.recenterOnShow = pred
}

// centerWhenReady centers w only on minimal WMs (recenterOnShow); elsewhere it
// returns so it never fights a user-moved window. On GTK4 an inline Center()
// no-ops until the GdkSurface is realized (async, after Show) and InvokeAsync
// would deadlock, so a background goroutine retries until Position is non-zero,
// bounded so a window genuinely at the origin can't spin forever.
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

// centerOnCursorScreen centers w on the cursor's display; guards no-op on headless sessions.
// On minimal WMs it uses the same realize-detection retry loop as centerWhenReady.
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

// title resolves a window-title i18n key in the current language, or the raw key if unavailable.
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

// retitleAll re-applies the localised title to every live auxiliary window. Pointers are
// snapshotted under s.mu; SetTitle is then safe to call after releasing the lock.
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

// restoreHiddenWindowsLocked re-shows windows hidden by hideOtherWindowsLocked
// (caller holds s.mu). If the main window was among them, raiseToForeground
// lifts it above the SSO browser, which still owns the foreground — a plain
// Show/Focus would be demoted to a taskbar flash and leave it stranded behind.
func (s *WindowManager) restoreHiddenWindowsLocked() {
	mainRestored := false
	for _, w := range s.hiddenForLogin {
		if w == nil {
			continue
		}
		w.Show()
		if w == s.mainWindow {
			mainRestored = true
		}
	}
	s.hiddenForLogin = nil
	if mainRestored && s.mainWindow != nil {
		raiseToForeground(s.mainWindow)
	}
}

// getScreenBasedOnCursorPosition returns the cursor's display, falling back to the
// main-window screen, then nil (OS-default placement).
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

// errorDialogURL builds the error window's start URL with title/message as escaped query params.
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

// u32ptr returns a pointer to v, for the optional *uint32 Wails theme fields.
func u32ptr(v uint32) *uint32 { return &v }
