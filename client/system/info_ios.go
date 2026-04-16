package system

import (
	"context"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

// UpdateStaticInfoAsync is a no-op on iOS as there is no static info to update
func UpdateStaticInfoAsync() {
	// do nothing
}

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {

	sysName := extractOsName(ctx, "sysName")
	swVersion := extractOsVersion(ctx, "swVersion")

	addrs, err := networkAddresses()
	if err != nil {
		log.Warnf("failed to discover network addresses: %s", err)
	}

	gio := &Info{
		Kernel:           sysName,
		OSVersion:        swVersion,
		Platform:         "unknown",
		OS:               sysName,
		GoOS:             runtime.GOOS,
		CPUs:             runtime.NumCPU(),
		KernelVersion:    swVersion,
		NetworkAddresses: addrs,
	}
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
