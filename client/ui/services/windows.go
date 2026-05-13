//go:build !android && !ios && !freebsd && !js

package services

import (
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// Windows opens auxiliary application windows on demand from the frontend.
// The main window is created up-front in main.go; this service is for
// secondary, on-demand surfaces (Settings).
//
// The settings window is created hidden at app startup so its React bundle is
// already loaded by the time the user clicks the Settings icon — OpenSettings
// then just shows and focuses the pre-warmed window. Closing the window hides
// it instead of destroying it, so reopening is also instant.
type Windows struct {
	app      *application.App
	settings *application.WebviewWindow
}

func NewWindows(app *application.App) *Windows {
	w := &Windows{app: app}
	w.settings = w.buildSettings()
	return w
}

func (s *Windows) buildSettings() *application.WebviewWindow {
	w := s.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "NetBird Settings",
		Width:            900,
		Height:           640,
		Hidden:           true,
		DisableResize:    true,
		MinimiseButtonState: application.ButtonHidden,
		MaximiseButtonState: application.ButtonHidden,
		CloseButtonState:    application.ButtonEnabled,
		BackgroundColour: application.NewRGB(24, 26, 29),
		URL:              "/#/settings",
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 38,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
			CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
		},
	})

	// Hide instead of close so the React bundle stays warm and the next
	// OpenSettings is instant — same trick the main window uses.
	w.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		w.Hide()
	})

	return w
}

// OpenSettings shows the pre-warmed settings window.
func (s *Windows) OpenSettings() {
	if s.settings == nil {
		return
	}
	s.settings.Show()
	s.settings.Focus()
}
