package system

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	"github.com/netbirdio/netbird/version"
)

type Win32_OperatingSystem struct {
	Caption string
}

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	osName, osVersion := getOSNameAndVersion()
	buildVersion := getBuildVersion()
	gio := &Info{Kernel: "windows", OSVersion: osVersion, Core: buildVersion, Platform: "unknown", OS: osName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, systemHostname)
	gio.WiretrusteeVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

func getOSNameAndVersion() (string, string) {
	var dst []Win32_OperatingSystem
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil {
		log.Error(err)
		return "Windows", getBuildVersion()
	}

	if len(dst) == 0 {
		return "Windows", getBuildVersion()
	}

	split := strings.Split(dst[0].Caption, " ")

	if len(split) < 3 {
		return "Windows", getBuildVersion()
	}

	name := split[1]
	version := split[2]
	if split[2] == "Server" {
		name = fmt.Sprintf("%s %s", split[1], split[2])
		version = split[3]
	}

	return name, version
}

func getBuildVersion() string {
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
