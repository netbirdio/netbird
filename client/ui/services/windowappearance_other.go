//go:build !darwin && !windows && !android && !ios && !freebsd && !js

package services

import (
	"unsafe"

	"github.com/netbirdio/netbird/client/ui/preferences"
)

// setWindowAppearance is a no-op wherever there is no per-window appearance to
// set, which is every target this file covers. On Linux the appearance is real
// but app-wide, so setAppAppearance owns it instead; on the remaining Unix
// targets there is no native theming to apply at all and setAppAppearance is
// itself a stub (appappearance_other.go).
func setWindowAppearance(unsafe.Pointer, preferences.Theme, bool) {}
