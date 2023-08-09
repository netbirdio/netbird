//go:build ios
// +build ios

package system

import (
	"context"
	"os"
	"runtime"

	"github.com/netbirdio/netbird/version"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {

	// Convert fixed-size byte arrays to Go strings
	sysName := "iOS"
	machine := "machine"
	release := "release"
	swversion := "swversion"

	gio := &Info{Kernel: sysName, OSVersion: swversion, Core: release, Platform: machine, OS: sysName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, systemHostname)
	gio.WiretrusteeVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}
