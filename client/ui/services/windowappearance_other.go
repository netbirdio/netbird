//go:build !darwin && !windows && !android && !ios && !freebsd && !js

package services

import (
	"unsafe"

	"github.com/netbirdio/netbird/client/ui/preferences"
)

// setWindowAppearance is a no-op on Linux: GTK styling is app-wide, so it is
// handled by setAppAppearance rather than per window.
func setWindowAppearance(unsafe.Pointer, preferences.Theme, bool) {}
