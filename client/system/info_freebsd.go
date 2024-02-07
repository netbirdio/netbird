package system

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/netbirdio/netbird/version"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	out := _getInfo()
	for strings.Contains(out, "broken pipe") {
		out = _getInfo()
		time.Sleep(500 * time.Millisecond)
	}
	osStr := strings.Replace(out, "\n", "", -1)
	osStr = strings.Replace(osStr, "\r\n", "", -1)
	osInfo := strings.Split(osStr, " ")
	gio := &Info{Kernel: osInfo[0], Platform: runtime.GOARCH, OS: osInfo[2], GoOS: runtime.GOOS, CPUs: runtime.NumCPU(), KernelVersion: osInfo[1]}
	systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, systemHostname)
	gio.WiretrusteeVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)
	gio.Cloud = detectCloud()

	log.Debugf("Cloud: %s", gio.Cloud)
	log.Debugf("SystemManufacturer: %s", gio.SystemManufacturer)
	log.Debugf("SystemProductName: %s", gio.SystemProductName)

	return gio
}

func _getInfo() string {
	cmd := exec.Command("uname", "-sri")
	cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("getInfo:", err)
	}
	return out.String()
}
