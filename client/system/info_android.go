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
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	kernel := "android"
	osInfo := uname()
	if len(osInfo) == 2 {
		kernel = osInfo[1]
	}

	gio := &Info{Kernel: kernel, Core: sdkVersion(), Platform: "unknown", OS: "android", OSVersion: sdkVersion(), GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	gio.Hostname = extractDeviceName(ctx)
	gio.WiretrusteeVersion = NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

func extractDeviceName(ctx context.Context) string {
	v, ok := ctx.Value(DeviceNameCtxKey).(string)
	if !ok {
		return ""
	}
	return v
}

func uname() []string {
	res := run("/system/bin/uname", "-a")
	return strings.Split(res, " ")
}

func sdkVersion() string {
	return run("/system/bin/getprop", "ro.build.version.sdk")
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
