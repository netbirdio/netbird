//go:build !darwin && !windows && !android && !ios && !freebsd && !js

package services

import (
	"unsafe"

	"github.com/netbirdio/netbird/client/ui/preferences"
)

// setWindowAppearance is a no-op on Linux; the chrome follows the GTK theme.
func setWindowAppearance(unsafe.Pointer, preferences.Theme, bool) {}
