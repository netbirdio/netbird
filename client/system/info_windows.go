package system

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
	"os"
	"runtime"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	ver := getOSVersion()
	gio := &Info{Kernel: "windows", OSVersion: ver, Core: ver, Platform: "unknown", OS: "windows", GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	gio.Hostname, _ = os.Hostname()
	gio.WiretrusteeVersion = NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

func getOSVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		log.Error(err)
		return "0.0.0.0"
	}
	defer func() {
		deferErr := k.Close()
		if deferErr != nil {
			log.Error(deferErr)
		}
	}()
	
	major, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		log.Error(err)
	}
	minor, _, err := k.GetIntegerValue("CurrentMinorVersionNumber")
	if err != nil {
		log.Error(err)
	}
	build, _, err := k.GetStringValue("CurrentBuildNumber")
	if err != nil {
		log.Error(err)
	}
	// Update Build Revision
	ubr, _, err := k.GetIntegerValue("UBR")
	if err != nil {
		log.Error(err)
	}
	ver := fmt.Sprintf("%d.%d.%s.%d", major, minor, build, ubr)
	return ver
}
