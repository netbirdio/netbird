//go:build !windows && !android && !ios && !freebsd && !js

package services

import "github.com/wailsapp/wails/v3/pkg/application"

func raiseToForeground(w *application.WebviewWindow) {
	if w != nil {
		w.Focus()
	}
}
