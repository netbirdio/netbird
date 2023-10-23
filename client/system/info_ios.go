//go:build ios
// +build ios

package system

import (
	"context"
	"runtime"

	"github.com/netbirdio/netbird/version"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {

	// Convert fixed-size byte arrays to Go strings
	sysName := extractOsName(ctx, "sysName")
	swVersion := extractOsVersion(ctx, "swVersion")

	gio := &Info{Kernel: sysName, OSVersion: swVersion, Core: swVersion, Platform: "unknown", OS: sysName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	// systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, "hostname")
	gio.WiretrusteeVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}
