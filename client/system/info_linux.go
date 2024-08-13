//go:build !android
// +build !android

package system

import (
	"bytes"
	"context"
	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zcalusic/sysinfo"

	"github.com/netbirdio/netbird/client/system/detect_cloud"
	"github.com/netbirdio/netbird/client/system/detect_platform"
	"github.com/netbirdio/netbird/version"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	info := _getInfo()
	for strings.Contains(info, "broken pipe") {
		info = _getInfo()
		time.Sleep(500 * time.Millisecond)
	}

	releaseInfo := _getReleaseInfo()
	for strings.Contains(info, "broken pipe") {
		releaseInfo = _getReleaseInfo()
		time.Sleep(500 * time.Millisecond)
	}

	osRelease := strings.Split(releaseInfo, "\n")
	var osName string
	var osVer string
	for _, s := range osRelease {
		if strings.HasPrefix(s, "NAME=") {
			osName = strings.Split(s, "=")[1]
			osName = strings.ReplaceAll(osName, "\"", "")
		} else if strings.HasPrefix(s, "VERSION_ID=") {
			osVer = strings.Split(s, "=")[1]
			osVer = strings.ReplaceAll(osVer, "\"", "")
		}
	}

	osStr := strings.ReplaceAll(info, "\n", "")
	osStr = strings.ReplaceAll(osStr, "\r\n", "")
	osInfo := strings.Split(osStr, " ")
	if osName == "" {
		osName = osInfo[3]
	}

	systemHostname, _ := os.Hostname()

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
		Kernel:             osInfo[0],
		Platform:           osInfo[2],
		OS:                 osName,
		OSVersion:          osVer,
		Hostname:           extractDeviceName(ctx, systemHostname),
		GoOS:               runtime.GOOS,
		CPUs:               runtime.NumCPU(),
		WiretrusteeVersion: version.NetbirdVersion(),
		UIVersion:          extractUserAgent(ctx),
		KernelVersion:      osInfo[1],
		NetworkAddresses:   addrs,
		SystemSerialNumber: serialNum,
		SystemProductName:  prodName,
		SystemManufacturer: manufacturer,
		Environment:        env,
		Ipv6Supported:      _checkIPv6Support(),
	}

	return gio
}

func _getInfo() string {
	cmd := exec.Command("uname", "-srio")
	cmd.Stdin = strings.NewReader("some")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Warnf("getInfo: %s", err)
	}
	return out.String()
}

func _getReleaseInfo() string {
	cmd := exec.Command("cat", "/etc/os-release")
	cmd.Stdin = strings.NewReader("some")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Warnf("geucwReleaseInfo: %s", err)
	}
	return out.String()
}

func sysInfo() (serialNumber string, productName string, manufacturer string) {
	var si sysinfo.SysInfo
	si.GetSysInfo()
	return si.Chassis.Serial, si.Product.Name, si.Product.Vendor
}

func _checkIPv6Support() bool {
	return firewall.SupportsIPv6() &&
		iface.SupportsIPv6()
}
