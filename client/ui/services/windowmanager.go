//go:build !android && !ios && !freebsd && !js

package services

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

// LanguageSubscriber delivers UI preference changes so window titles follow the language.
type LanguageSubscriber interface {
	Subscribe() (<-chan preferences.UIPreferences, func())
}

type windowOp func(w *application.WebviewWindow, created bool)

type windowCloser func(w *application.WebviewWindow)

// hideableWindow is the slice of application.Window the hide/restore bookkeeping needs.
// Narrow enough to fake in tests, which application.Window itself is not: it carries
// unexported methods.
type hideableWindow interface {
	Show() application.Window
	Hide() application.Window
	IsVisible() bool
	Name() string
}

// EventTriggerLogin asks the frontend's startLogin() to begin an SSO flow.
const EventTriggerLogin = "trigger-login"

// EventBrowserLoginCancel signals the user dismissed the BrowserLogin popup.
const EventBrowserLoginCancel = "browser-login:cancel"

// EventSettingsOpen tells the mounted settings window which tab to show.
const EventSettingsOpen = "netbird:settings:open"

const EventWindowPainted = "netbird:window-painted"

// generationParam carries the painted-report token in each dialog's start URL.
const generationParam = "gen"

const paintedFallback = 3 * time.Second

const headlessTeardownDelay = 2 * time.Second

const (
	windowMain              = "main"
	windowSettings          = "settings"
	windowBrowserLogin      = "browser-login"
	windowSessionExpiration = "session-expiration"
	windowInstallProgress   = "install-progress"
	windowWelcome           = "welcome"
	windowError             = "error"
)

// Window background per effective appearance. Both match the body background
// (bg-nb-gray DEFAULT) in globals.css so opaque native pixels and the webview
// paint the same surface; keep the three in sync.
var (
	windowBackgroundDark  = application.NewRGB(24, 26, 29)    // dark nb-gray DEFAULT
	windowBackgroundLight = application.NewRGB(243, 243, 243) // light nb-gray DEFAULT
)

// Appearance is one view of the theme state: the preference and the appearance
// it resolves to. Take it once per window with CurrentAppearance and pass the
// same value to every option builder -- Pref drives the macOS frame while Dark
// drives the background and the Windows chrome, so reading them separately can
// build a window with a new background behind the previous native frame.
type Appearance struct {
	Pref preferences.Theme
	Dark bool
}

// storedAppearance is the snapshot maintained by services.Theme, published as
// one value so the pair can never tear. It is the fallback for window creation
// until resolveAppearance is installed.
var storedAppearance atomic.Value // Appearance

// resolveAppearance re-resolves against the live OS state. Theme installs it so
// window creation never reads a stale seed: app.Env.IsDarkMode reports light
// until Run installs the platform layer, and Wails runs every
// ApplicationStarted listener in its own goroutine, so a startup window can be
// created before Theme's listener has corrected the seed.
var resolveAppearance atomic.Value // func() Appearance

func init() {
	storedAppearance.Store(Appearance{Pref: preferences.DefaultTheme, Dark: true})
}

func setAppearance(pref preferences.Theme, dark bool) {
	storedAppearance.Store(Appearance{Pref: pref, Dark: dark})
}

func setAppearanceResolver(f func() Appearance) { resolveAppearance.Store(f) }

// CurrentAppearance returns the snapshot every window creation must build from.
func CurrentAppearance() Appearance {
	if f, _ := resolveAppearance.Load().(func() Appearance); f != nil {
		return f()
	}
	a, _ := storedAppearance.Load().(Appearance)
	return a
}

// WindowBackgroundColour returns the background for a snapshot; use it for
// every WebviewWindowOptions.BackgroundColour.
func WindowBackgroundColour(a Appearance) application.RGBA {
	return windowBackgroundColour(a.Dark)
}

// windowBackgroundColour maps a resolved appearance to its window background.
func windowBackgroundColour(dark bool) application.RGBA {
	if dark {
		return windowBackgroundDark
	}
	return windowBackgroundLight
}

// WindowHeight is shared by the main and Settings windows.
const WindowHeight = 660

// Wails reads CustomTheme colours as 0x00BBGGRR (RGB byte order reversed).
var microsoftWindowsDarkTheme = &application.WindowTheme{
	BorderColour:    u32ptr(0x00211E1C), // #1C1E21 nb-gray-940
	TitleBarColour:  u32ptr(0x00211E1C),
	TitleTextColour: u32ptr(0x00E9E7E4), // #E4E7E9 nb-gray-100
}

var microsoftWindowsLightTheme = &application.WindowTheme{
	BorderColour:    u32ptr(0x00F3F3F3), // #F3F3F3 light nb-gray DEFAULT
	TitleBarColour:  u32ptr(0x00F3F3F3),
	TitleTextColour: u32ptr(0x00212121), // #212121 light nb-gray-100
}

// MicrosoftWindowsAppearanceOptions is the shared Windows chrome (Mica +
// custom title bar), resolved at creation; setWindowAppearance re-themes live
// windows on later changes. Never SystemDefault: Wails gives those windows a
// SystemThemeChanged handler that re-themes chrome from the OS appearance,
// which outlives a switch to a forced theme and fights it on the next OS flip.
// Both CustomTheme slots hold one colour set for the same reason.
func MicrosoftWindowsAppearanceOptions(a Appearance) application.WindowsWindow {
	theme, chrome := application.Light, microsoftWindowsLightTheme
	if a.Dark {
		theme, chrome = application.Dark, microsoftWindowsDarkTheme
	}
	return application.WindowsWindow{
		BackdropType: application.Mica,
		Theme:        theme,
		CustomTheme: application.ThemeSettings{
			DarkModeActive:    chrome,
			DarkModeInactive:  chrome,
			LightModeActive:   chrome,
			LightModeInactive: chrome,
		},
	}
}

// AppleMacOSAppearanceOptions is the shared macOS chrome; FullScreenNone keeps the fixed-size layout.
func AppleMacOSAppearanceOptions(a Appearance) application.MacWindow {
	appearance := application.DefaultAppearance
	switch a.Pref {
	case preferences.ThemeLight:
		appearance = application.NSAppearanceNameAqua
	case preferences.ThemeDark:
		appearance = application.NSAppearanceNameDarkAqua
	}
	return application.MacWindow{
		InvisibleTitleBarHeight: 38,
		Backdrop:                application.MacBackdropNormal,
		TitleBar:                application.MacTitleBarHiddenInset,
		CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
		Appearance:              appearance,
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
	a := CurrentAppearance()
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
		BackgroundColour:    WindowBackgroundColour(a),
		URL:                 url,
		Mac:                 AppleMacOSAppearanceOptions(a),
		Windows:             MicrosoftWindowsAppearanceOptions(a),
		Linux:               LinuxAppearanceOptions(linuxIcon),
	}
}

// hiddenWindow records a window hidden by owner, the name of the popup that hid it.
type hiddenWindow struct {
	win   hideableWindow
	owner string
}

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
	// hiddenWindows holds windows hidden while a popup owns the screen, each tagged with
	// the popup that hid it so closing one popup cannot restore what another still hides.
	hiddenWindows []hiddenWindow
	// allWindows and raiseMain are the seams the hide/restore tests replace; both are nil
	// in production, where the Wails app and the platform helper are used directly.
	allWindows   func() []hideableWindow
	raiseMain    func()
	mu           sync.Mutex
	newMain      func(startURL string) *application.WebviewWindow
	creating     map[string]bool
	pendingOps   map[string][]windowOp
	pendingClose map[string]windowCloser
	restoreGen   map[string]uint64
	// painted gates showing a window: set by the frontend's first render, or by the
	// fallback timer so a webview that never wakes up still becomes visible.
	painted map[uint]bool
	// mounted gates emitting to a window: set only by a real frontend report, since an
	// event emitted to a frontend that has not subscribed yet is dropped, not queued.
	mounted        map[uint]bool
	showPending    map[uint]bool
	pendingTab     map[uint]string
	pendingEmits   map[uint][]string
	fallbackTimers map[uint]*time.Timer
	afterShow      map[uint]func()
	// generation maps a window name to the token stamped into its current start URL, so a
	// painted report from a replaced window can be told apart from the live one's.
	generation     map[string]uint64
	lastGeneration uint64
	headlessMain   bool
	headlessTimer  *time.Timer
	// recenterOnShow is set only on the minimal-WM/XEmbed path, where the WM neither centers nor
	// restores position; nil on full desktops so re-centering can't fight a user-moved window.
	recenterOnShow func() bool
}

func NewWindowManager(app *application.App, mainWindow *application.WebviewWindow, translator ErrorTranslator, prefs LanguagePreference, linuxIcon []byte) *WindowManager {
	s := &WindowManager{
		app:            app,
		mainWindow:     mainWindow,
		translator:     translator,
		prefs:          prefs,
		linuxIcon:      linuxIcon,
		creating:       map[string]bool{},
		pendingOps:     map[string][]windowOp{},
		pendingClose:   map[string]windowCloser{},
		restoreGen:     map[string]uint64{},
		painted:        map[uint]bool{},
		mounted:        map[uint]bool{},
		showPending:    map[uint]bool{},
		pendingTab:     map[uint]string{},
		pendingEmits:   map[uint][]string{},
		fallbackTimers: map[uint]*time.Timer{},
		afterShow:      map[uint]func(){},
		generation:     map[string]uint64{},
	}
	s.watchPainted()
	s.watchTriggerLogin()
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
	return s
}

func (s *WindowManager) newSettingsWindow() *application.WebviewWindow {
	a := CurrentAppearance()
	w := s.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:                windowSettings,
		Title:               s.title("window.title.settings"),
		Width:               900,
		Height:              WindowHeight,
		Hidden:              true,
		DisableResize:       true,
		MinimiseButtonState: application.ButtonHidden,
		MaximiseButtonState: application.ButtonHidden,
		CloseButtonState:    application.ButtonEnabled,
		BackgroundColour:    WindowBackgroundColour(a),
		URL:                 "/#/settings",
		Mac:                 AppleMacOSAppearanceOptions(a),
		Windows:             MicrosoftWindowsAppearanceOptions(a),
		Linux:               LinuxAppearanceOptions(s.linuxIcon),
	})
	w.RegisterHook(events.Common.WindowClosing, func(_ *application.WindowEvent) {
		s.mu.Lock()
		s.settings = nil
		s.forgetWindowLocked(w)
		s.mu.Unlock()
	})
	s.armReady(w)
	return w
}

// OpenSettings shows the settings window on tab (empty → General), switching tab via
// EventSettingsOpen rather than SetURL (which would remount the provider tree).
func (s *WindowManager) OpenSettings(tab string) {
	target := tab
	if target == "" {
		target = "general"
	}

	s.withWindow(windowSettings, &s.settings, s.newSettingsWindow, func(w *application.WebviewWindow, _ bool) {
		s.mu.Lock()
		mounted := s.mounted[w.ID()]
		if !mounted {
			s.pendingTab[w.ID()] = target
		}
		s.mu.Unlock()

		if mounted {
			s.app.Event.Emit(EventSettingsOpen, target)
		}
		s.showWhenReady(w)
	})
}

// OpenBrowserLogin shows the SSO popup, creating it on first use.
func (s *WindowManager) OpenBrowserLogin(uri string) {
	startURL := "/#/dialog/browser-login"
	if uri != "" {
		startURL = "/#/dialog/browser-login?uri=" + url.QueryEscape(uri)
	}
	s.withWindow(windowBrowserLogin, &s.browserLogin, func() *application.WebviewWindow {
		return s.newBrowserLoginWindow(s.stampGeneration(windowBrowserLogin, startURL))
	}, func(w *application.WebviewWindow, created bool) {
		if !created && uri != "" {
			w.SetURL(s.stampGeneration(windowBrowserLogin, startURL))
		}
		s.centerOnCursorScreen(w)
		s.showThenOpenBrowser(w, uri)
	})
}

func (s *WindowManager) showThenOpenBrowser(w *application.WebviewWindow, uri string) {
	if uri != "" {
		s.mu.Lock()
		s.afterShow[w.ID()] = func() { s.openBrowser(uri) }
		s.mu.Unlock()
	}
	s.showWhenReady(w)
}

func (s *WindowManager) openBrowser(uri string) {
	if uri == "" {
		return
	}
	go func() {
		if err := openURL(uri); err != nil {
			log.Errorf("open browser for SSO login: %v", err)
			s.OpenError(s.title("browserLogin.openFailedTitle"), err.Error(), "")
		}
	}()
}

func (s *WindowManager) newBrowserLoginWindow(startURL string) *application.WebviewWindow {
	s.hideOtherWindows(windowBrowserLogin)
	opts := DialogWindowOptions(windowBrowserLogin, s.title("window.title.signIn"), startURL, s.linuxIcon)
	// Not always-on-top: it would obscure the browser tab the user logs in through.
	opts.AlwaysOnTop = false
	opts.InitialPosition = application.WindowCentered
	// Open on the active (where users cursor is) display, like the session-expiration dialog.
	opts.Screen = s.getScreenBasedOnCursorPosition()
	w := s.app.Window.NewWithOptions(opts)
	w.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
		s.mu.Lock()
		// Only a live user red-X still has this registered; programmatic closers
		// nil s.browserLogin first and clean up themselves. Guarding here stops a
		// stale close event from wiping a replacement popup's state.
		userClosed := s.browserLogin == w
		if userClosed {
			s.browserLogin = nil
		}
		s.forgetWindowLocked(w)
		s.mu.Unlock()
		if userClosed {
			s.restoreHiddenWindows(windowBrowserLogin)
			s.app.Event.Emit(EventBrowserLoginCancel)
		}
	})
	s.armReady(w)
	return w
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
	// The WindowClosing hook no-ops on a programmatic close, so the closer restores.
	// The frontend calls this even when no popup was ever shown (resetDialog() after an
	// early RequestExtend failure, or connection.ts's catch path); closeWindow skips the
	// closer then, and an owner-scoped restore cannot touch what install-progress hides.
	s.closeWindow(windowBrowserLogin, &s.browserLogin, s.restoringCloser(windowBrowserLogin))
}

// OpenSessionExpiration shows the countdown warning on the cursor's display; seconds seeds
// the countdown and deadlineUnixMilli (0 when unknown) is the absolute deadline the dialog
// compares renewal snapshots against. Singleton, destroyed on close.
func (s *WindowManager) OpenSessionExpiration(seconds int, deadlineUnixMilli int64) {
	startURL := "/#/dialog/session-expiration?seconds=" + strconv.Itoa(seconds)
	if deadlineUnixMilli > 0 {
		startURL += "&deadline=" + strconv.FormatInt(deadlineUnixMilli, 10)
	}
	s.withWindow(windowSessionExpiration, &s.sessionExpiration, func() *application.WebviewWindow {
		return s.newSessionExpirationWindow(s.stampGeneration(windowSessionExpiration, startURL))
	}, func(w *application.WebviewWindow, created bool) {
		if !created {
			w.SetURL(s.stampGeneration(windowSessionExpiration, startURL))
		}
		s.centerOnCursorScreen(w)
		s.showWhenReady(w)
	})
}

func (s *WindowManager) newSessionExpirationWindow(startURL string) *application.WebviewWindow {
	opts := DialogWindowOptions(windowSessionExpiration, s.title("window.title.sessionExpiration"), startURL, s.linuxIcon)
	opts.Screen = s.getScreenBasedOnCursorPosition()
	opts.InitialPosition = application.WindowCentered
	w := s.app.Window.NewWithOptions(opts)
	w.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
		s.mu.Lock()
		if s.sessionExpiration == w {
			s.sessionExpiration = nil
		}
		s.forgetWindowLocked(w)
		s.mu.Unlock()
	})
	s.armReady(w)
	return w
}

func (s *WindowManager) CloseSessionExpiration() {
	s.closeWindow(windowSessionExpiration, &s.sessionExpiration, closeOnly)
}

// CloseRenewFlow tears down the SSO session-renewal UI in a single call: it
// closes the browser-login popup and the session-expiration window together.
func (s *WindowManager) CloseRenewFlow() {
	s.mu.Lock()
	bl := s.takeWindowLocked(windowBrowserLogin, &s.browserLogin, s.restoringCloser(windowBrowserLogin))
	se := s.takeWindowLocked(windowSessionExpiration, &s.sessionExpiration, closeOnly)
	if se != nil {
		kept := s.hiddenWindows[:0]
		for _, hidden := range s.hiddenWindows {
			if !sameWindow(hidden.win, se) {
				kept = append(kept, hidden)
			}
		}
		s.hiddenWindows = kept
	}
	s.mu.Unlock()

	s.restoreHiddenWindows(windowBrowserLogin)
	// Close after unlock so the re-entrant handlers can take s.mu.
	if bl != nil {
		bl.Close()
	}
	if se != nil {
		se.Close()
	}
}

// OpenInstallProgress shows the install-progress window and hides the rest for the duration
// (restored on close). It owns its own result polling since the daemon restarts mid-install.
func (s *WindowManager) OpenInstallProgress(version string) {
	startURL := "/#/dialog/install-progress"
	if version != "" {
		startURL = "/#/dialog/install-progress?version=" + url.QueryEscape(version)
	}
	s.withWindow(windowInstallProgress, &s.installProgress, func() *application.WebviewWindow {
		return s.newInstallProgressWindow(s.stampGeneration(windowInstallProgress, startURL))
	}, func(w *application.WebviewWindow, created bool) {
		if !created {
			w.SetURL(s.stampGeneration(windowInstallProgress, startURL))
		}
		s.showWhenReady(w)
	})
}

func (s *WindowManager) newInstallProgressWindow(startURL string) *application.WebviewWindow {
	s.hideOtherWindows(windowInstallProgress)
	w := s.app.Window.NewWithOptions(
		DialogWindowOptions(windowInstallProgress, s.title("window.title.updating"), startURL, s.linuxIcon),
	)
	w.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
		s.mu.Lock()
		userClosed := s.installProgress == w
		if userClosed {
			s.installProgress = nil
		}
		s.forgetWindowLocked(w)
		s.mu.Unlock()
		if userClosed {
			s.restoreHiddenWindows(windowInstallProgress)
		}
	})
	s.armReady(w)
	return w
}

func (s *WindowManager) CloseInstallProgress() {
	s.closeWindow(windowInstallProgress, &s.installProgress, s.restoringCloser(windowInstallProgress))
}

// OpenWelcome shows the first-launch onboarding window. Singleton, destroyed on close.
func (s *WindowManager) OpenWelcome() {
	s.withWindow(windowWelcome, &s.welcome, s.newWelcomeWindow, func(w *application.WebviewWindow, _ bool) {
		s.showWhenReady(w)
	})
}

func (s *WindowManager) newWelcomeWindow() *application.WebviewWindow {
	opts := DialogWindowOptions(windowWelcome, s.title("window.title.welcome"), s.stampGeneration(windowWelcome, "/#/dialog/welcome"), s.linuxIcon)
	opts.Width = 420
	opts.InitialPosition = application.WindowCentered
	w := s.app.Window.NewWithOptions(opts)
	w.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
		s.mu.Lock()
		if s.welcome == w {
			s.welcome = nil
		}
		s.forgetWindowLocked(w)
		s.mu.Unlock()
	})
	s.armReady(w)
	return w
}

func (s *WindowManager) CloseWelcome() {
	s.closeWindow(windowWelcome, &s.welcome, closeOnly)
}

// OpenError shows the custom error dialog; title/message/command are pre-localised
// and ride in the start URL. command is optional and, when set, is offered for
// copying so the user can run the operation the daemon refused. A second error
// replaces the open one via SetURL. Singleton, destroyed on close.
func (s *WindowManager) OpenError(title, message, command string) {
	if ShuttingDown() {
		return
	}
	startURL := errorDialogURL(title, message, command)
	s.withWindow(windowError, &s.errorDialog, func() *application.WebviewWindow {
		return s.newErrorWindow(s.stampGeneration(windowError, startURL))
	}, func(w *application.WebviewWindow, created bool) {
		if !created {
			w.SetURL(s.stampGeneration(windowError, startURL))
		}
		s.showWhenReady(w)
	})
}

func (s *WindowManager) newErrorWindow(startURL string) *application.WebviewWindow {
	w := s.app.Window.NewWithOptions(
		DialogWindowOptions(windowError, s.title("window.title.error"), startURL, s.linuxIcon),
	)
	w.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
		s.mu.Lock()
		if s.errorDialog == w {
			s.errorDialog = nil
		}
		s.forgetWindowLocked(w)
		s.mu.Unlock()
	})
	s.armReady(w)
	return w
}

func (s *WindowManager) CloseError() {
	s.closeWindow(windowError, &s.errorDialog, closeOnly)
}

// OpenMain brings the main window forward; the welcome handoff uses it instead of the tray.
func (s *WindowManager) OpenMain() {
	s.ShowMain()
}

// ShowMain brings the main window forward (re-centering on minimal WMs). The single entry
// point every surface (tray, SIGUSR1, welcome) should use so centering applies uniformly.
func (s *WindowManager) ShowMain() {
	s.ensureMain("/", func(w *application.WebviewWindow, _ bool) {
		s.showWhenReady(w)
	})
}

// ShowMainAndEmit brings the main window forward and emits event once its frontend is ready.
func (s *WindowManager) ShowMainAndEmit(event string) {
	s.ensureMain("/", func(w *application.WebviewWindow, _ bool) {
		id := w.ID()
		s.mu.Lock()
		mounted := s.mounted[id]
		if !mounted {
			s.pendingEmits[id] = append(s.pendingEmits[id], event)
		}
		s.mu.Unlock()

		s.showWhenReady(w)
		if mounted {
			s.app.Event.Emit(event)
		}
	})
}

func (s *WindowManager) MainWindow() *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mainWindow
}

func (s *WindowManager) ensureMain(startURL string, op windowOp) {
	s.mu.Lock()
	factory := s.newMain
	s.mu.Unlock()
	if factory == nil {
		s.withWindow(windowMain, &s.mainWindow, nil, op)
		return
	}
	s.withWindow(windowMain, &s.mainWindow, func() *application.WebviewWindow {
		w := factory(startURL)
		s.armReady(w)
		return w
	}, op)
}

func (s *WindowManager) withWindow(name string, slot **application.WebviewWindow, factory func() *application.WebviewWindow, op windowOp) {
	s.mu.Lock()
	if s.creating[name] {
		s.pendingOps[name] = append(s.pendingOps[name], op)
		s.mu.Unlock()
		return
	}
	if w := *slot; w != nil {
		s.mu.Unlock()
		op(w, false)
		return
	}
	if factory == nil {
		s.mu.Unlock()
		return
	}
	s.creating[name] = true
	s.mu.Unlock()

	w := s.createWindow(name, slot, factory)
	if w == nil {
		return
	}
	s.finishCreation(name, slot, w, op)
}

func (s *WindowManager) createWindow(name string, slot **application.WebviewWindow, factory func() *application.WebviewWindow) *application.WebviewWindow {
	created := false
	defer func() {
		if created {
			return
		}
		s.mu.Lock()
		s.releaseCreationLocked(name)
		s.mu.Unlock()
	}()

	w := factory()
	if w == nil {
		return nil
	}
	s.mu.Lock()
	*slot = w
	s.mu.Unlock()
	created = true
	return w
}

func (s *WindowManager) finishCreation(name string, slot **application.WebviewWindow, w *application.WebviewWindow, op windowOp) {
	finished := false
	defer func() {
		if finished {
			return
		}
		s.mu.Lock()
		s.releaseCreationLocked(name)
		s.mu.Unlock()
	}()

	created := true
	for {
		s.mu.Lock()
		if closer := s.pendingClose[name]; closer != nil {
			if *slot == w {
				*slot = nil
			}
			s.releaseCreationLocked(name)
			finished = true
			s.mu.Unlock()
			closer(w)
			return
		}
		var next windowOp
		switch {
		case created:
			next = op
		case len(s.pendingOps[name]) > 0:
			next = s.pendingOps[name][0]
			s.pendingOps[name] = s.pendingOps[name][1:]
		default:
			s.releaseCreationLocked(name)
			finished = true
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		next(w, created)
		created = false
	}
}

func (s *WindowManager) closeWindow(name string, slot **application.WebviewWindow, closer windowCloser) {
	s.mu.Lock()
	w := s.takeWindowLocked(name, slot, closer)
	s.mu.Unlock()
	if w != nil {
		closer(w)
	}
}

func (s *WindowManager) takeWindowLocked(name string, slot **application.WebviewWindow, closer windowCloser) *application.WebviewWindow {
	if s.creating[name] {
		if s.pendingClose[name] == nil {
			s.pendingClose[name] = closer
		}
		return nil
	}
	w := *slot
	*slot = nil
	return w
}

func (s *WindowManager) releaseCreationLocked(name string) {
	delete(s.creating, name)
	delete(s.pendingOps, name)
	delete(s.pendingClose, name)
}

func (s *WindowManager) restoringCloser(owner string) windowCloser {
	return func(w *application.WebviewWindow) {
		s.restoreHiddenWindows(owner)
		w.Close()
	}
}

// armReady starts the fallback that shows w even if its frontend never reports a first
// render. The timer starts at creation, because a hidden webview can be suspended before
// it reaches WindowRuntimeReady — the very case this fallback covers. That makes the first
// budget cover webview boot as well, so the runtime-ready hook rearms it to give the
// frontend its own full budget to mount and paint.
func (s *WindowManager) armReady(w *application.WebviewWindow) {
	if w == nil {
		return
	}
	s.armPaintedFallback(w)
	w.RegisterHook(events.Common.WindowRuntimeReady, func(_ *application.WindowEvent) {
		s.armPaintedFallback(w)
	})
}

func (s *WindowManager) armPaintedFallback(w *application.WebviewWindow) {
	id := w.ID()
	timer := time.AfterFunc(paintedFallback, func() {
		s.mu.Lock()
		painted := s.painted[id]
		s.mu.Unlock()
		if painted {
			return
		}
		log.Warnf("window %q never reported a first render, showing it anyway", w.Name())
		s.markPainted(w)
	})

	s.mu.Lock()
	if prev := s.fallbackTimers[id]; prev != nil {
		prev.Stop()
	}
	if s.painted[id] {
		timer.Stop()
		delete(s.fallbackTimers, id)
	} else {
		s.fallbackTimers[id] = timer
	}
	s.mu.Unlock()
}

func (s *WindowManager) watchPainted() {
	s.app.Event.On(EventWindowPainted, func(e *application.CustomEvent) {
		w := s.windowByName(e.Sender)
		if w == nil {
			return
		}
		if !s.matchesGeneration(e.Sender, paintedGeneration(e.Data)) {
			log.Debugf("ignoring stale painted report for window %q", e.Sender)
			return
		}
		s.markPainted(w)
		s.markMounted(w)
	})
}

func (s *WindowManager) watchTriggerLogin() {
	s.app.Event.On(EventTriggerLogin, func(_ *application.CustomEvent) {
		s.mu.Lock()
		if s.headlessTimer != nil {
			s.headlessTimer.Stop()
			s.headlessTimer = nil
		}
		w := s.mainWindow
		ready := w != nil && s.mounted[w.ID()]
		s.mu.Unlock()
		if ready {
			return
		}

		s.ensureMain("/", func(w *application.WebviewWindow, created bool) {
			s.mu.Lock()
			if created {
				s.headlessMain = true
			}
			pending := !s.mounted[w.ID()]
			if pending {
				s.pendingEmits[w.ID()] = append(s.pendingEmits[w.ID()], EventTriggerLogin)
			}
			s.mu.Unlock()

			if !pending {
				s.app.Event.Emit(EventTriggerLogin)
			}
		})
	})

	s.app.Event.On(EventBrowserLoginCancel, func(_ *application.CustomEvent) {
		s.scheduleHeadlessTeardown()
	})

	s.app.Event.On(EventStatusSnapshot, func(e *application.CustomEvent) {
		st, ok := e.Data.(Status)
		if !ok {
			return
		}
		switch st.Status {
		case StatusConnected, StatusLoginFailed, StatusDaemonUnavailable:
			s.scheduleHeadlessTeardown()
		}
	})
}

func (s *WindowManager) scheduleHeadlessTeardown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.headlessMain || s.mainWindow == nil {
		return
	}
	if s.headlessTimer != nil {
		s.headlessTimer.Stop()
	}
	s.headlessTimer = time.AfterFunc(headlessTeardownDelay, s.closeHeadlessMain)
}

func (s *WindowManager) closeHeadlessMain() {
	s.mu.Lock()
	w := s.mainWindow
	headless := s.headlessMain
	s.headlessTimer = nil
	s.mu.Unlock()
	if !headless || w == nil {
		return
	}
	w.Close()
}

func (s *WindowManager) forgetWindowLocked(w *application.WebviewWindow) {
	if w == nil {
		return
	}

	id := w.ID()
	if timer := s.fallbackTimers[id]; timer != nil {
		timer.Stop()
	}
	delete(s.fallbackTimers, id)
	delete(s.painted, id)
	delete(s.mounted, id)
	delete(s.showPending, id)
	delete(s.pendingTab, id)
	delete(s.pendingEmits, id)
	delete(s.afterShow, id)

	kept := s.hiddenWindows[:0]
	for _, hidden := range s.hiddenWindows {
		if !sameWindow(hidden.win, w) {
			kept = append(kept, hidden)
		}
	}
	s.hiddenWindows = kept
}

func (s *WindowManager) stampGeneration(name, startURL string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastGeneration++
	s.generation[name] = s.lastGeneration
	return appendGeneration(startURL, s.lastGeneration)
}

func (s *WindowManager) matchesGeneration(name string, gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	want, tracked := s.generation[name]
	if !tracked {
		return true
	}
	return want == gen
}

func (s *WindowManager) hideableWindows() []hideableWindow {
	if s.allWindows != nil {
		return s.allWindows()
	}
	all := s.app.Window.GetAll()
	windows := make([]hideableWindow, 0, len(all))
	for _, w := range all {
		windows = append(windows, w)
	}
	return windows
}

func (s *WindowManager) isMainWindow(w hideableWindow, mainWindow *application.WebviewWindow) bool {
	if s.allWindows != nil {
		return w != nil && w.Name() == windowMain
	}
	return sameWindow(w, mainWindow)
}

func (s *WindowManager) raiseMainWindow(mainWindow *application.WebviewWindow) {
	if s.raiseMain != nil {
		s.raiseMain()
		return
	}
	if mainWindow != nil {
		raiseToForeground(mainWindow)
	}
}

func (s *WindowManager) windowByName(name string) *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch name {
	case windowMain:
		return s.mainWindow
	case windowSettings:
		return s.settings
	case windowBrowserLogin:
		return s.browserLogin
	case windowSessionExpiration:
		return s.sessionExpiration
	case windowInstallProgress:
		return s.installProgress
	case windowWelcome:
		return s.welcome
	case windowError:
		return s.errorDialog
	default:
		return nil
	}
}

func (s *WindowManager) markPainted(w *application.WebviewWindow) {
	id := w.ID()
	s.mu.Lock()
	already := s.painted[id]
	s.painted[id] = true
	wanted := s.showPending[id]
	delete(s.showPending, id)
	if timer := s.fallbackTimers[id]; timer != nil {
		timer.Stop()
		delete(s.fallbackTimers, id)
	}
	s.mu.Unlock()

	if already || !wanted {
		return
	}
	s.showNow(w)
}

// markMounted records that the window's frontend is subscribed, and flushes the events
// held back for it. The fallback timer never calls this: showing a blank window is
// recoverable, emitting into a frontend that cannot hear it is not.
func (s *WindowManager) markMounted(w *application.WebviewWindow) {
	id := w.ID()
	s.mu.Lock()
	already := s.mounted[id]
	s.mounted[id] = true
	tab, hasTab := s.pendingTab[id]
	emits := s.pendingEmits[id]
	delete(s.pendingTab, id)
	delete(s.pendingEmits, id)
	s.mu.Unlock()

	if already {
		return
	}

	if hasTab {
		s.app.Event.Emit(EventSettingsOpen, tab)
	}

	for _, event := range emits {
		s.app.Event.Emit(event)
	}
}

func (s *WindowManager) showWhenReady(w *application.WebviewWindow) {
	if w == nil {
		return
	}

	id := w.ID()
	s.mu.Lock()
	painted := s.painted[id]
	if !painted {
		s.showPending[id] = true
	}
	s.mu.Unlock()

	if painted {
		s.showNow(w)
	}
}

func (s *WindowManager) showNow(w *application.WebviewWindow) {
	id := w.ID()
	s.mu.Lock()
	if w == s.mainWindow {
		s.headlessMain = false
		if s.headlessTimer != nil {
			s.headlessTimer.Stop()
			s.headlessTimer = nil
		}
	}
	after := s.afterShow[id]
	delete(s.afterShow, id)
	s.mu.Unlock()
	w.Show()
	w.Focus()
	s.centerWhenReady(w)
	if after != nil {
		after()
	}
}

func (s *WindowManager) ShowMainAt(url string) {
	s.ensureMain(url, func(w *application.WebviewWindow, created bool) {
		if !created {
			w.SetURL(url)
		}
		s.showWhenReady(w)
	})
}

func (s *WindowManager) SetMainFactory(f func(startURL string) *application.WebviewWindow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.newMain = f
}

func (s *WindowManager) ForgetMain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgetWindowLocked(s.mainWindow)
	s.mainWindow = nil
	s.headlessMain = false
	if s.headlessTimer != nil {
		s.headlessTimer.Stop()
		s.headlessTimer = nil
	}
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

// hideOtherWindows hides every visible window except keepName, recording them against
// keepName so only its own restore brings them back. A window already hidden by an
// earlier popup is skipped, leaving it tagged to the popup that actually hid it. The
// per-owner generation catches a restore for keepName that ran between the snapshot and
// the record, in which case the windows are re-shown rather than stranded.
func (s *WindowManager) hideOtherWindows(keepName string) {
	s.mu.Lock()
	gen := s.restoreGen[keepName]
	s.mu.Unlock()

	var hidden []hideableWindow
	for _, w := range s.hideableWindows() {
		if w == nil || w.Name() == keepName || !w.IsVisible() {
			continue
		}
		w.Hide()
		hidden = append(hidden, w)
	}
	if len(hidden) == 0 {
		return
	}

	s.mu.Lock()
	restored := s.restoreGen[keepName] != gen
	if !restored {
		for _, w := range hidden {
			s.hiddenWindows = append(s.hiddenWindows, hiddenWindow{win: w, owner: keepName})
		}
	}
	s.mu.Unlock()
	if !restored {
		return
	}
	for _, w := range hidden {
		w.Show()
	}
}

// restoreHiddenWindows re-shows the windows owner hid, leaving those another popup still
// hides untouched. If the main window was among them, raiseToForeground lifts it above
// the SSO browser, which still owns the foreground — a plain Show/Focus would be demoted
// to a taskbar flash and leave it stranded behind.
func (s *WindowManager) restoreHiddenWindows(owner string) {
	s.mu.Lock()
	mainWindow := s.mainWindow
	var restore []hideableWindow
	kept := s.hiddenWindows[:0]
	for _, hidden := range s.hiddenWindows {
		if hidden.owner != owner {
			kept = append(kept, hidden)
			continue
		}
		if hidden.win != nil {
			restore = append(restore, hidden.win)
		}
	}
	s.hiddenWindows = kept
	s.restoreGen[owner]++
	s.mu.Unlock()

	mainRestored := false
	for _, w := range restore {
		w.Show()
		if s.isMainWindow(w, mainWindow) {
			mainRestored = true
		}
	}
	if mainRestored {
		s.raiseMainWindow(mainWindow)
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
	s.mu.Lock()
	mainWindow := s.mainWindow
	s.mu.Unlock()
	if mainWindow != nil {
		if sc, err := mainWindow.GetScreen(); err == nil {
			return sc
		}
	}
	return nil
}

// errorDialogURL builds the error window's start URL with title/message/command as escaped query params.
func errorDialogURL(title, message, command string) string {
	q := url.Values{}
	if title != "" {
		q.Set("title", title)
	}
	if message != "" {
		q.Set("message", message)
	}
	if command != "" {
		q.Set("command", command)
	}
	startURL := "/#/dialog/error"
	if enc := q.Encode(); enc != "" {
		startURL += "?" + enc
	}
	return startURL
}

// appendGeneration adds the painted-report token to a dialog start URL, keeping any
// existing query params intact across the "/#/path?params" hash-router form.
func appendGeneration(startURL string, gen uint64) string {
	sep := "?"
	if strings.Contains(startURL, "?") {
		sep = "&"
	}
	return startURL + sep + generationParam + "=" + strconv.FormatUint(gen, 10)
}

// paintedGeneration reads the token a painted report carries back, returning 0 when the
// frontend sent none (an older bundle, or the main window, which is never stamped).
func paintedGeneration(data any) uint64 {
	switch v := data.(type) {
	case string:
		gen, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0
		}
		return gen
	case float64:
		return uint64(v)
	case []any:
		if len(v) == 0 {
			return 0
		}
		return paintedGeneration(v[0])
	default:
		return 0
	}
}

// sameWindow reports whether a hidden entry refers to w, comparing through the interface
// so a nil entry never matches a live window.
func sameWindow(hidden hideableWindow, w *application.WebviewWindow) bool {
	if hidden == nil || w == nil {
		return false
	}
	other, ok := hidden.(*application.WebviewWindow)
	return ok && other == w
}

// u32ptr returns a pointer to v, for the optional *uint32 Wails theme fields.
func u32ptr(v uint32) *uint32 { return &v }

func closeOnly(w *application.WebviewWindow) { w.Close() }
