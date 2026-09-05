//go:build windows

package services

import (
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/w32"
)

func getCursorPosition(app *application.App) (application.Point, bool) {
	x, y, ok := w32.GetCursorPos()
	if !ok || app == nil || app.Screen == nil {
		return application.Point{}, false
	}
	// GetCursorPos is in physical pixels; Screen.Bounds is in DIPs.
	return app.Screen.PhysicalToDipPoint(application.Point{X: x, Y: y}), true
}
