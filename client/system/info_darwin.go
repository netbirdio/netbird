//go:build !ios
// +build !ios

package system

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/system/detect_cloud"
	"github.com/netbirdio/netbird/client/system/detect_platform"
	"github.com/netbirdio/netbird/version"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	utsname := unix.Utsname{}
	err := unix.Uname(&utsname)
	if err != nil {
		log.Warnf("getInfo: %s", err)
	}
	sysName := string(bytes.Split(utsname.Sysname[:], []byte{0})[0])
	machine := string(bytes.Split(utsname.Machine[:], []byte{0})[0])
	release := string(bytes.Split(utsname.Release[:], []byte{0})[0])
	swVersion, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		log.Warnf("got an error while retrieving macOS version with sw_vers, error: %s. Using darwin version instead.\n", err)
		swVersion = []byte(release)
	}

	addrs, err := networkAddresses()
	if err != nil {
		log.Warnf("failed to discover network addresses: %s", err)
	}

	serialNum, prodName, manufacturer := sysInfo()

	env := Environment{
		Cloud:    detect_cloud.Detect(ctx),
		Platform: detect_platform.Detect(ctx),
	}

	gio := &Info{
		Kernel:             sysName,
		OSVersion:          strings.TrimSpace(string(swVersion)),
		Platform:           machine,
		OS:                 sysName,
		GoOS:               runtime.GOOS,
		CPUs:               runtime.NumCPU(),
		KernelVersion:      release,
		NetworkAddresses:   addrs,
		SystemSerialNumber: serialNum,
		SystemProductName:  prodName,
		SystemManufacturer: manufacturer,
		Environment:        env,
		Ipv6Supported:      false,
	}

	systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, systemHostname)
	gio.WiretrusteeVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

func sysInfo() (serialNumber string, productName string, manufacturer string) {
	out, _ := exec.Command("/usr/sbin/ioreg", "-l").Output() // err ignored for brevity
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "IOPlatformSerialNumber") {
			serialNumber = trimIoRegLine(l)
		}

		if strings.Contains(l, "ModelNumber") && productName == "" {
			productName = trimIoRegLine(l)
		}

		if strings.Contains(l, "device manufacturer") && manufacturer == "" {
			manufacturer = trimIoRegLine(l)
		}

	}
	return
}

func trimIoRegLine(l string) string {
	kv := strings.Split(l, "=")
	if len(kv) != 2 {
		return ""
	}
	s := strings.TrimSpace(kv[1])
	return strings.Trim(s, `"`)
}
