package system

import (
	"context"
	"runtime"

	"github.com/netbirdio/netbird/version"
)

// UpdateStaticInfoAsync is a no-op on Android as there is no static info to update
func UpdateStaticInfoAsync() {
	// do nothing
}

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {

	// Convert fixed-size byte arrays to Go strings
	sysName := extractOsName(ctx, "sysName")
	swVersion := extractOsVersion(ctx, "swVersion")

	gio := &Info{Kernel: sysName, OSVersion: swVersion, Platform: "unknown", OS: sysName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU(), KernelVersion: swVersion}
	gio.Hostname = extractDeviceName(ctx, "hostname")
	gio.NetbirdVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

// checkFileAndProcess checks if the file path exists and if a process is running at that path.
func checkFileAndProcess(paths []string) ([]File, error) {
	return []File{}, nil
}

// extractOsVersion extracts operating system version from context or returns the default
func extractOsVersion(ctx context.Context, defaultName string) string {
	v, ok := ctx.Value(OsVersionCtxKey).(string)
	if !ok {
		return defaultName
	}
	return v
}

// extractOsName extracts operating system name from context or returns the default
func extractOsName(ctx context.Context, defaultName string) string {
	v, ok := ctx.Value(OsNameCtxKey).(string)
	if !ok {
		return defaultName
	}
	return v
}
