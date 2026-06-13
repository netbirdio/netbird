//go:build !darwin && !windows && !linux

package services

import "github.com/wailsapp/wails/v3/pkg/application"

func getCursorPosition(_ *application.App) (application.Point, bool) {
	return application.Point{}, false
}
