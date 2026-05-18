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
	app                   *application.App
	settings              *application.WebviewWindow
	browserLogin          *application.WebviewWindow
	sessionExpired        *application.WebviewWindow
	sessionAboutToExpire  *application.WebviewWindow
	mu                    sync.Mutex
}

func NewWindowManager(app *application.App) *WindowManager {
	return &WindowManager{app: app}
}

// OpenSettings shows the settings window, creating it on first use (and
// after the user has closed a previous instance).
func (s *WindowManager) OpenSettings() {
	s.mu.Lock()
	defer s.mu.Unlock()
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
			URL:                 "/#/settings",
			Mac: application.MacWindow{
				InvisibleTitleBarHeight: 38,
				Backdrop:                application.MacBackdropTranslucent,
				TitleBar:                application.MacTitleBarHiddenInset,
				CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
			},
		})
		s.settings.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.settings = nil
			s.mu.Unlock()
		})
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
		s.browserLogin = s.app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:                "browser-login",
			Title:               "NetBird Sign-in",
			Width:               460,
			Height:              440,
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
		})
		bl := s.browserLogin
		// User-initiated close (red X) means cancel. Emit the event so
		// startLogin() can tear the SSO wait down, then let the window
		// destroy naturally — no hide trickery.
		bl.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.app.Event.Emit(EventBrowserLoginCancel)
			s.mu.Lock()
			s.browserLogin = nil
			s.mu.Unlock()
		})
	} else if uri != "" {
		s.browserLogin.SetURL("/#/browser-login?uri=" + url.QueryEscape(uri))
	}
	s.browserLogin.Show()
	s.browserLogin.Focus()
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
func (s *WindowManager) OpenSessionExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionExpired == nil {
		s.sessionExpired = s.app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:                "session-expired",
			Title:               "NetBird",
			Width:               460,
			Height:              380,
			DisableResize:       true,
			AlwaysOnTop:         true,
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
		})
		s.sessionExpired.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.sessionExpired = nil
			s.mu.Unlock()
		})
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
func (s *WindowManager) OpenSessionAboutToExpire(seconds int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	startURL := "/#/session-about-to-expire?seconds=" + strconv.Itoa(seconds)
	if s.sessionAboutToExpire == nil {
		s.sessionAboutToExpire = s.app.Window.NewWithOptions(application.WebviewWindowOptions{
			Name:                "session-about-to-expire",
			Title:               "NetBird",
			Width:               460,
			Height:              380,
			DisableResize:       true,
			AlwaysOnTop:         true,
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
		})
		s.sessionAboutToExpire.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) {
			s.mu.Lock()
			s.sessionAboutToExpire = nil
			s.mu.Unlock()
		})
	} else {
		s.sessionAboutToExpire.SetURL(startURL)
	}
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
