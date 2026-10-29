//go:build !darwin && !windows && !linux && !freebsd && !android && !ios && !js

package services

import "github.com/wailsapp/wails/v3/pkg/application"

func getCursorPosition(_ *application.App) (application.Point, bool) {
	return application.Point{}, false
}
