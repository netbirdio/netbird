//go:build !android && !ios && !freebsd && !js

package services

import (
	"net/url"
	"strconv"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// EventTriggerLogin asks the frontend's startLogin() orchestrator to begin
// an SSO flow. Emitted by the tray (Login menu item, session expired) since
// the tray can't call JS directly.
const EventTriggerLogin = "trigger-login"

// EventBrowserLoginCancel is emitted by the BrowserLogin popup window when
// the user clicks Cancel or closes the window. startLogin() listens for it
// and tears down the daemon's pending SSO wait.
const EventBrowserLoginCancel = "browser-login:cancel"

// WindowManager opens auxiliary application windows on demand from the
// frontend. The main window is created up-front in main.go; this service is
// for secondary, on-demand surfaces (Settings, BrowserLogin).
//
// Secondary windows are created on first open and destroyed on close —
// the Wails-recommended singleton pattern (see Multiple Windows docs:
// "Cleanup on close"). Destroying rather than hiding means the dock-reopen
// handler doesn't find a hidden window to resurrect.
type WindowManager struct {
	app                  *application.App
	mainWindow           *application.WebviewWindow
	settings             *application.WebviewWindow
	browserLogin         *application.WebviewWindow
	sessionExpired       *application.WebviewWindow
	sessionAboutToExpire *application.WebviewWindow
	installProgress      *application.WebviewWindow
	// hiddenForLogin remembers windows that were visible when the
	// BrowserLogin popup opened. They were Hide()n to keep focus on the
	// SSO flow without resorting to AlwaysOnTop, and are restored when
	// the BrowserLogin window closes (success or cancel).
	hiddenForLogin []application.Window
	mu             sync.Mutex
}

// NewWindowManager wires the manager to the main app. `mainWindow` is the
// up-front-created webview the user interacts with from the tray — used to
// pick the BrowserLogin window's display so the sign-in popup follows the
// user onto the screen they're already looking at.
func NewWindowManager(app *application.App, mainWindow *application.WebviewWindow) *WindowManager {
	return &WindowManager{app: app, mainWindow: mainWindow}
}

// OpenSettings shows the settings window, creating it on first use (and
// after the user has closed a previous instance). If `tab` is non-empty the
// settings React layer reads it from the start URL and selects that tab
// (e.g. "profiles") instead of the default "general".
func (s *WindowManager) OpenSettings(tab string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	startURL := "/#/settings"
	if tab != "" {
		startURL = "/#/settings?tab=" + url.QueryEscape(tab)
	}
	if s.settings == nil {
		s.settings = s.app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:                "settings",
			Title:               "NetBird Settings",
			Width:               900,
			Height:              640,
			DisableResize:       true,
			MinimiseButtonState: application.ButtonHidden,
			MaximiseButtonState: application.ButtonHidden,
			CloseButtonState:    application.ButtonEnabled,
			BackgroundColour:    application.NewRGB(24, 26, 29),
			URL:                 startURL,
			Mac: application.MacWindow{
				InvisibleTitleBarHeight: 38,
				Backdrop:                application.MacBackdropTranslucent,
				TitleBar:                application.MacTitleBarHiddenInset,
				CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
			},
			Windows: application.WindowsWindow{
				Theme: application.Dark,
			},
		})
		s.settings.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.settings = nil
			s.mu.Unlock()
		})
	} else if tab != "" {
		// Re-open onto a specific tab when the window is already alive.
		s.settings.SetURL(startURL)
	}
	s.settings.Show()
	s.settings.Focus()
}

// OpenBrowserLogin shows the SSO popup window, creating it on first use (and
// after the user has closed a previous instance). The URI is encoded into
// the window's start URL so the React page reads it via useSearchParams.
func (s *WindowManager) OpenBrowserLogin(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.browserLogin == nil {
		startURL := "/#/browser-login"
		if uri != "" {
			startURL = "/#/browser-login?uri=" + url.QueryEscape(uri)
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
		s.browserLogin = s.app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:                "browser-login",
			Title:               "NetBird Sign-in",
			Width:               360,
			Height:              320,
			DisableResize:       true,
			// Hidden so the React side can measure its content via
			// useAutoSizeWindow and call Window.SetSize + Show before the
			// user sees the placeholder snapping to the measured height,
			// matching the Session* windows.
			Hidden:              true,
			// WindowCentered + Screen centers on the chosen display's
			// WorkArea (see WebviewWindowOptions.Screen docs).
			InitialPosition:     application.WindowCentered,
			Screen:              screen,
			MinimiseButtonState: application.ButtonHidden,
			MaximiseButtonState: application.ButtonHidden,
			CloseButtonState:    application.ButtonEnabled,
			BackgroundColour:    application.NewRGB(24, 26, 29),
			URL:                 startURL,
			Mac: application.MacWindow{
				InvisibleTitleBarHeight: 38,
				Backdrop:                application.MacBackdropTranslucent,
				TitleBar:                application.MacTitleBarHiddenInset,
				CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
			},
			Windows: application.WindowsWindow{
				Theme: application.Dark,
			},
		})
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
		// measured height.
		return
	}
	if uri != "" {
		s.browserLogin.SetURL("/#/browser-login?uri=" + url.QueryEscape(uri))
	}
	s.browserLogin.Show()
	s.browserLogin.Focus()
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

// OpenSessionExpired shows the "session expired" prompt window above all
// other application windows. Singleton — destroyed on close.
//
// The window is created Hidden so the React side can measure its content
// and call Window.SetSize + Window.Show before the user sees the chrome —
// otherwise the user would briefly see the 360x320 placeholder snapping to
// the measured height. Re-opens (singleton already alive) Show/Focus
// directly here.
func (s *WindowManager) OpenSessionExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionExpired == nil {
		s.sessionExpired = s.app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:                "session-expired",
			Title:               "NetBird",
			Width:               360,
			Height:              320,
			DisableResize:       true,
			AlwaysOnTop:         true,
			Hidden:              true,
			MinimiseButtonState: application.ButtonHidden,
			MaximiseButtonState: application.ButtonHidden,
			CloseButtonState:    application.ButtonEnabled,
			BackgroundColour:    application.NewRGB(24, 26, 29),
			URL:                 "/#/session-expired",
			Mac: application.MacWindow{
				InvisibleTitleBarHeight: 38,
				Backdrop:                application.MacBackdropTranslucent,
				TitleBar:                application.MacTitleBarHiddenInset,
				CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
			},
			Windows: application.WindowsWindow{
				Theme: application.Dark,
			},
		})
		s.sessionExpired.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.sessionExpired = nil
			s.mu.Unlock()
		})
		return
	}
	s.sessionExpired.Show()
	s.sessionExpired.Focus()
}

// CloseSessionExpired destroys the session-expired window if open.
func (s *WindowManager) CloseSessionExpired() {
	s.mu.Lock()
	w := s.sessionExpired
	s.sessionExpired = nil
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

// OpenSessionAboutToExpire shows the countdown warning window above all
// other application windows. `seconds` seeds the initial countdown value
// rendered as mm:ss in the React layer. Singleton — destroyed on close.
// Window is created Hidden so the React side can auto-size before paint
// (see OpenSessionExpired comment).
func (s *WindowManager) OpenSessionAboutToExpire(seconds int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	startURL := "/#/session-about-to-expire?seconds=" + strconv.Itoa(seconds)
	if s.sessionAboutToExpire == nil {
		s.sessionAboutToExpire = s.app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:                "session-about-to-expire",
			Title:               "NetBird",
			Width:               360,
			Height:              320,
			DisableResize:       true,
			AlwaysOnTop:         true,
			Hidden:              true,
			MinimiseButtonState: application.ButtonHidden,
			MaximiseButtonState: application.ButtonHidden,
			CloseButtonState:    application.ButtonEnabled,
			BackgroundColour:    application.NewRGB(24, 26, 29),
			URL:                 startURL,
			Mac: application.MacWindow{
				InvisibleTitleBarHeight: 38,
				Backdrop:                application.MacBackdropTranslucent,
				TitleBar:                application.MacTitleBarHiddenInset,
				CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
			},
			Windows: application.WindowsWindow{
				Theme: application.Dark,
			},
		})
		s.sessionAboutToExpire.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.sessionAboutToExpire = nil
			s.mu.Unlock()
		})
		return
	}
	s.sessionAboutToExpire.SetURL(startURL)
	s.sessionAboutToExpire.Show()
	s.sessionAboutToExpire.Focus()
}

// CloseSessionAboutToExpire destroys the countdown warning window if open.
func (s *WindowManager) CloseSessionAboutToExpire() {
	s.mu.Lock()
	w := s.sessionAboutToExpire
	s.sessionAboutToExpire = nil
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
	startURL := "/#/install-progress"
	if version != "" {
		startURL = "/#/install-progress?version=" + url.QueryEscape(version)
	}
	if s.installProgress == nil {
		s.hideOtherWindowsLocked("install-progress")
		s.installProgress = s.app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:                "install-progress",
			Title:               "NetBird",
			Width:               360,
			Height:              320,
			DisableResize:       true,
			AlwaysOnTop:         true,
			Hidden:              true,
			MinimiseButtonState: application.ButtonHidden,
			MaximiseButtonState: application.ButtonHidden,
			CloseButtonState:    application.ButtonEnabled,
			BackgroundColour:    application.NewRGB(24, 26, 29),
			URL:                 startURL,
			Mac: application.MacWindow{
				InvisibleTitleBarHeight: 38,
				Backdrop:                application.MacBackdropTranslucent,
				TitleBar:                application.MacTitleBarHiddenInset,
				CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
			},
			Windows: application.WindowsWindow{
				Theme: application.Dark,
			},
		})
		s.installProgress.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.installProgress = nil
			s.restoreHiddenWindowsLocked()
			s.mu.Unlock()
		})
		return
	}
	s.installProgress.SetURL(startURL)
	s.installProgress.Show()
	s.installProgress.Focus()
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
