//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/version"
)

// Version is the Wails-bound facade exposing build/version metadata to the
// frontend. Today it only reports the GUI's own version (the daemon version is
// surfaced separately through the status feed's DaemonVersion field).
type Version struct{}

// NewVersion constructs the Version service.
func NewVersion() *Version {
	return &Version{}
}

// GUI returns the version of the running UI binary, baked in at build time via
// the version package's ldflags. Falls back to "development" for un-stamped
// builds (see version.NetbirdVersion).
func (v *Version) GUI(_ context.Context) string {
	return version.NetbirdVersion()
}
