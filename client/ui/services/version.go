//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/version"
)

// Version is the Wails-bound facade exposing the GUI version baked in at
// build time via -ldflags. The tray reads version.NetbirdVersion() directly;
// this service exists so the React layer can show the same string instead
// of the static placeholder in frontend/package.json.
type Version struct{}

func NewVersion() *Version {
	return &Version{}
}

// GUI returns the GUI version string (e.g. "0.65.0" in release builds,
// "development" in dev builds).
func (s *Version) GUI(_ context.Context) (string, error) {
	return version.NetbirdVersion(), nil
}
