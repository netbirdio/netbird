//go:build !darwin && !android && !ios && !freebsd && !js

package services

import (
	"unsafe"

	"github.com/netbirdio/netbird/client/ui/preferences"
)

// setWindowAppearance is macOS-only; Windows chrome is themed via
// MicrosoftWindowsAppearanceOptions and Linux follows the GTK theme.
func setWindowAppearance(unsafe.Pointer, preferences.Theme) {}
