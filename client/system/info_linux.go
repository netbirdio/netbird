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

	"github.com/netbirdio/netbird/version"
)

var sisInfoWrapper SysInfo

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

	start := time.Now()
	si := updateStaticInfo()
	if time.Since(start) > 1*time.Second {
		log.Infof("updateStaticInfo took %s", time.Since(start))
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
		SystemSerialNumber: si.SystemSerialNumber,
		SystemProductName:  si.SystemProductName,
		SystemManufacturer: si.SystemManufacturer,
		Environment:        si.Environment,
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

func sysInfo() (string, string, string) {
	isascii := regexp.MustCompile("^[[:ascii:]]+$")

	serials := []string{sisInfoWrapper.ChassisSerial, sisInfoWrapper.ProductSerial}
	serial := ""

	for _, s := range serials {
		if isascii.MatchString(s) {
			serial = s
			if s != "Default string" {
				break
			}
		}
	}

	if serial == "" && isascii.MatchString(sisInfoWrapper.BoardSerial) {
		serial = sisInfoWrapper.BoardSerial
	}

	var name string
	for _, n := range []string{sisInfoWrapper.ProductName, sisInfoWrapper.BoardName} {
		if isascii.MatchString(n) {
			name = n
			break
		}
	}

	var manufacturer string
	if isascii.MatchString(sisInfoWrapper.ProductVendor) {
		manufacturer = sisInfoWrapper.ProductVendor
	}
	return serial, name, manufacturer
}
