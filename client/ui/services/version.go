//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/version"
)

// Version reports only the GUI's own version; the daemon version comes from
// the status feed's DaemonVersion field.
type Version struct{}

func NewVersion() *Version {
	return &Version{}
}

// GUI returns the UI binary's version, stamped via ldflags ("development" if un-stamped).
func (v *Version) GUI(_ context.Context) string {
	return version.NetbirdVersion()
}
