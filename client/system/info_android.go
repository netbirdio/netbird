//go:build android
// +build android

package system

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	kernel := "android"
	osInfo := uname()
	if len(osInfo) == 2 {
		kernel = osInfo[1]
	}

	var kernelVersion string
	if len(osInfo) > 2 {
		kernelVersion = osInfo[2]
	}

	gio := &Info{
		GoOS:               runtime.GOOS,
		Kernel:             kernel,
		Platform:           "unknown",
		OS:                 "android",
		OSVersion:          osVersion(),
		Hostname:           extractDeviceName(ctx, "android"),
		CPUs:               runtime.NumCPU(),
		WiretrusteeVersion: version.NetbirdVersion(),
		UIVersion:          extractUIVersion(ctx),
		KernelVersion:      kernelVersion,
		Ipv6Supported:      false,
	}

	return gio
}

func uname() []string {
	res := run("/system/bin/uname", "-a")
	return strings.Split(res, " ")
}

func osVersion() string {
	return run("/system/bin/getprop", "ro.build.version.release")
}

func extractUIVersion(ctx context.Context) string {
	v, ok := ctx.Value(UiVersionCtxKey).(string)
	if !ok {
		return ""
	}
	return v
}

func run(name string, arg ...string) string {
	cmd := exec.Command(name, arg...)
	cmd.Stdin = strings.NewReader("some")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Errorf("getInfo: %s", err)
	}
	return out.String()
}
