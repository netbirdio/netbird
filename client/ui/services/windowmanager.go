//go:build !android && !ios && !freebsd && !js

package services

import (
	"net/url"
	"strconv"
	"sync"
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

// EventTriggerLogin asks the frontend's startLogin() to begin an SSO flow.
const EventTriggerLogin = "trigger-login"

// EventBrowserLoginCancel signals the user dismissed the BrowserLogin popup.
const EventBrowserLoginCancel = "browser-login:cancel"

// EventSettingsOpen tells the mounted settings window which tab to show.
const EventSettingsOpen = "netbird:settings:open"

const EventWindowPainted = "netbird:window-painted"

const paintedFallback = 2 * time.Second

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
	newMain        func(startURL string) *application.WebviewWindow
	creating       map[string]bool
	pendingOps     map[string][]windowOp
	ready          map[uint]bool
	showPending    map[uint]bool
	pendingTab     map[uint]string
	pendingEmits   map[uint][]string
	fallbackTimers map[uint]*time.Timer
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
		ready:          map[uint]bool{},
		showPending:    map[uint]bool{},
		pendingTab:     map[uint]string{},
		pendingEmits:   map[uint][]string{},
		fallbackTimers: map[uint]*time.Timer{},
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
		BackgroundColour:    WindowBackgroundColour,
		URL:                 "/#/settings",
		Mac:                 AppleMacOSAppearanceOptions(),
		Windows:             MicrosoftWindowsAppearanceOptions(),
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
		ready := s.ready[w.ID()]
		if !ready {
			s.pendingTab[w.ID()] = target
		}
		s.mu.Unlock()

		if ready {
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
		return s.newBrowserLoginWindow(startURL)
	}, func(w *application.WebviewWindow, created bool) {
		if created {
			s.centerOnCursorScreen(w)
			return
		}
		if uri != "" {
			w.SetURL(startURL)
		}
		s.centerOnCursorScreen(w)
		w.Show()
		w.Focus()
	})
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
		s.mu.Unlock()
		if userClosed {
			s.restoreHiddenWindows()
			s.app.Event.Emit(EventBrowserLoginCancel)
		}
	})
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
	s.mu.Lock()
	w := s.browserLogin
	s.browserLogin = nil
	s.mu.Unlock()
	// The WindowClosing hook no-ops on a programmatic close, so restore here —
	// but only if a popup was actually open. The frontend calls this even when no
	// popup was ever shown (e.g. resetDialog() after an early RequestExtend failure,
	// or connection.ts's catch path), and hiddenForLogin is shared with
	// OpenInstallProgress, so an unconditional restore could re-show windows a
	// still-running install-progress is hiding.
	if w == nil {
		return
	}
	s.restoreHiddenWindows()
	w.Close()
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
		return s.newSessionExpirationWindow(startURL)
	}, func(w *application.WebviewWindow, created bool) {
		if created {
			s.centerOnCursorScreen(w)
			return
		}
		w.SetURL(startURL)
		s.centerOnCursorScreen(w)
		w.Show()
		w.Focus()
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
		s.mu.Unlock()
	})
	return w
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

// CloseRenewFlow tears down the SSO session-renewal UI in a single call: it
// closes the browser-login popup and the session-expiration window together.
func (s *WindowManager) CloseRenewFlow() {
	s.mu.Lock()
	bl := s.browserLogin
	se := s.sessionExpiration
	s.browserLogin = nil
	s.sessionExpiration = nil
	if se != nil {
		kept := s.hiddenForLogin[:0]
		for _, w := range s.hiddenForLogin {
			if w != se {
				kept = append(kept, w)
			}
		}
		s.hiddenForLogin = kept
	}
	s.mu.Unlock()

	s.restoreHiddenWindows()
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
		return s.newInstallProgressWindow(startURL)
	}, func(w *application.WebviewWindow, created bool) {
		if !created {
			w.SetURL(startURL)
			w.Show()
			w.Focus()
		}
		s.centerWhenReady(w)
	})
}

func (s *WindowManager) newInstallProgressWindow(startURL string) *application.WebviewWindow {
	s.hideOtherWindows(windowInstallProgress)
	w := s.app.Window.NewWithOptions(
		DialogWindowOptions(windowInstallProgress, s.title("window.title.updating"), startURL, s.linuxIcon),
	)
	w.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
		s.mu.Lock()
		if s.installProgress == w {
			s.installProgress = nil
		}
		s.mu.Unlock()
		s.restoreHiddenWindows()
	})
	return w
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
	s.withWindow(windowWelcome, &s.welcome, s.newWelcomeWindow, func(w *application.WebviewWindow, created bool) {
		if !created {
			w.Show()
			w.Focus()
		}
		s.centerWhenReady(w)
	})
}

func (s *WindowManager) newWelcomeWindow() *application.WebviewWindow {
	opts := DialogWindowOptions(windowWelcome, s.title("window.title.welcome"), "/#/dialog/welcome", s.linuxIcon)
	opts.Width = 420
	opts.InitialPosition = application.WindowCentered
	w := s.app.Window.NewWithOptions(opts)
	w.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
		s.mu.Lock()
		if s.welcome == w {
			s.welcome = nil
		}
		s.mu.Unlock()
	})
	return w
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
		return s.newErrorWindow(startURL)
	}, func(w *application.WebviewWindow, created bool) {
		if !created {
			w.SetURL(startURL)
			w.Show()
			w.Focus()
		}
		s.centerWhenReady(w)
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
		s.mu.Unlock()
	})
	return w
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
	s.ensureMain("/", func(w *application.WebviewWindow, _ bool) {
		s.showWhenReady(w)
	})
}

// ShowMainAndEmit brings the main window forward and emits event once its frontend is ready.
func (s *WindowManager) ShowMainAndEmit(event string) {
	s.ensureMain("/", func(w *application.WebviewWindow, _ bool) {
		id := w.ID()
		s.mu.Lock()
		ready := s.ready[id]
		if !ready {
			s.pendingEmits[id] = append(s.pendingEmits[id], event)
		}
		s.mu.Unlock()

		s.showWhenReady(w)
		if ready {
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
	if w := *slot; w != nil {
		s.mu.Unlock()
		op(w, false)
		return
	}
	if factory == nil {
		s.mu.Unlock()
		return
	}
	if s.creating[name] {
		s.pendingOps[name] = append(s.pendingOps[name], op)
		s.mu.Unlock()
		return
	}
	s.creating[name] = true
	s.mu.Unlock()

	w := factory()

	s.mu.Lock()
	*slot = w
	delete(s.creating, name)
	queued := s.pendingOps[name]
	delete(s.pendingOps, name)
	s.mu.Unlock()

	if w == nil {
		return
	}
	op(w, true)
	for _, queuedOp := range queued {
		queuedOp(w, false)
	}
}

func (s *WindowManager) armReady(w *application.WebviewWindow) {
	if w == nil {
		return
	}
	w.RegisterHook(events.Common.WindowRuntimeReady, func(_ *application.WindowEvent) {
		timer := time.AfterFunc(paintedFallback, func() {
			log.Warnf("window %q never reported a first render, showing it anyway", w.Name())
			s.markReady(w)
		})
		s.mu.Lock()
		s.fallbackTimers[w.ID()] = timer
		s.mu.Unlock()
	})
}

func (s *WindowManager) watchPainted() {
	s.app.Event.On(EventWindowPainted, func(e *application.CustomEvent) {
		if w := s.windowByName(e.Sender); w != nil {
			s.markReady(w)
		}
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
		ready := w != nil && s.ready[w.ID()]
		s.mu.Unlock()
		if ready {
			return
		}

		s.ensureMain("/", func(w *application.WebviewWindow, created bool) {
			s.mu.Lock()
			if created {
				s.headlessMain = true
			}
			pending := !s.ready[w.ID()]
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
	delete(s.ready, id)
	delete(s.showPending, id)
	delete(s.pendingTab, id)
	delete(s.pendingEmits, id)

	kept := s.hiddenForLogin[:0]
	for _, hidden := range s.hiddenForLogin {
		if hidden != application.Window(w) {
			kept = append(kept, hidden)
		}
	}
	s.hiddenForLogin = kept
}

func (s *WindowManager) windowByName(name string) *application.WebviewWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch name {
	case windowMain:
		return s.mainWindow
	case windowSettings:
		return s.settings
	default:
		return nil
	}
}

func (s *WindowManager) markReady(w *application.WebviewWindow) {
	id := w.ID()
	s.mu.Lock()
	already := s.ready[id]
	s.ready[id] = true
	wanted := s.showPending[id]
	tab, hasTab := s.pendingTab[id]
	emits := s.pendingEmits[id]
	if timer := s.fallbackTimers[id]; timer != nil {
		timer.Stop()
		delete(s.fallbackTimers, id)
	}
	delete(s.showPending, id)
	delete(s.pendingTab, id)
	delete(s.pendingEmits, id)
	s.mu.Unlock()

	if already {
		return
	}

	if hasTab {
		s.app.Event.Emit(EventSettingsOpen, tab)
	}

	if wanted {
		s.showNow(w)
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
	ready := s.ready[id]
	if !ready {
		s.showPending[id] = true
	}
	s.mu.Unlock()

	if ready {
		s.showNow(w)
	}
}

func (s *WindowManager) showNow(w *application.WebviewWindow) {
	s.mu.Lock()
	if w == s.mainWindow {
		s.headlessMain = false
		if s.headlessTimer != nil {
			s.headlessTimer.Stop()
			s.headlessTimer = nil
		}
	}
	s.mu.Unlock()
	w.Show()
	w.Focus()
	s.centerWhenReady(w)
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

func (s *WindowManager) hideOtherWindows(keepName string) {
	var hidden []application.Window
	for _, w := range s.app.Window.GetAll() {
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
	s.hiddenForLogin = append(s.hiddenForLogin, hidden...)
	s.mu.Unlock()
}

// restoreHiddenWindows re-shows windows hidden by hideOtherWindows. If the main
// window was among them, raiseToForeground lifts it above the SSO browser, which
// still owns the foreground — a plain Show/Focus would be demoted to a taskbar
// flash and leave it stranded behind.
func (s *WindowManager) restoreHiddenWindows() {
	s.mu.Lock()
	hidden := s.hiddenForLogin
	s.hiddenForLogin = nil
	mainWindow := s.mainWindow
	s.mu.Unlock()

	mainRestored := false
	for _, w := range hidden {
		if w == nil {
			continue
		}
		w.Show()
		if w == mainWindow {
			mainRestored = true
		}
	}
	if mainRestored && mainWindow != nil {
		raiseToForeground(mainWindow)
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

// u32ptr returns a pointer to v, for the optional *uint32 Wails theme fields.
func u32ptr(v uint32) *uint32 { return &v }
