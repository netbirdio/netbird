//go:build !android
// +build !android

package system

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zcalusic/sysinfo"

	"github.com/netbirdio/netbird/client/system/detect_cloud"
	"github.com/netbirdio/netbird/client/system/detect_platform"
	"github.com/netbirdio/netbird/version"
)

type SysInfoGetter interface {
	GetSysInfo() SysInfo
}

type SysInfoWrapper struct {
	si sysinfo.SysInfo
}

func (s SysInfoWrapper) GetSysInfo() SysInfo {
	s.si.GetSysInfo()
	return SysInfo{
		ChassisSerial: s.si.Chassis.Serial,
		ProductSerial: s.si.Product.Serial,
		BoardSerial:   s.si.Board.Serial,
		ProductName:   s.si.Product.Name,
		BoardName:     s.si.Board.Name,
		ProductVendor: s.si.Product.Vendor,
	}
}

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	info := _getInfo()
	for strings.Contains(info, "broken pipe") {
		info = _getInfo()
		time.Sleep(500 * time.Millisecond)
	}

	osStr := strings.ReplaceAll(info, "\n", "")
	osStr = strings.ReplaceAll(osStr, "\r\n", "")
	osInfo := strings.Split(osStr, " ")

	osName, osVersion := readOsReleaseFile()
	if osName == "" {
		osName = osInfo[3]
	}

	systemHostname, _ := os.Hostname()

	addrs, err := networkAddresses()
	if err != nil {
		log.Warnf("failed to discover network addresses: %s", err)
	}

	si := SysInfoWrapper{}
	serialNum, prodName, manufacturer := sysInfo(si.GetSysInfo())

	env := Environment{
		Cloud:    detect_cloud.Detect(ctx),
		Platform: detect_platform.Detect(ctx),
	}

	gio := &Info{
		Kernel:             osInfo[0],
		Platform:           osInfo[2],
		OS:                 osName,
		OSVersion:          osVersion,
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

func sysInfo(si SysInfo) (string, string, string) {
	isascii := regexp.MustCompile("^[[:ascii:]]+$")

	serials := []string{si.ChassisSerial, si.ProductSerial}
	serial := ""

	for _, s := range serials {
		if isascii.MatchString(s) {
			serial = s
			if s != "Default string" {
				break
			}
		}
	}

	if serial == "" && isascii.MatchString(si.BoardSerial) {
		serial = si.BoardSerial
	}

	var name string
	for _, n := range []string{si.ProductName, si.BoardName} {
		if isascii.MatchString(n) {
			name = n
			break
		}
	}

	var manufacturer string
	if isascii.MatchString(si.ProductVendor) {
		manufacturer = si.ProductVendor
	}
	return serial, name, manufacturer
}
