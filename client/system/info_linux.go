//go:build !android

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

var (
	// it is override in tests
	getSystemInfo = defaultSysInfoImplementation
)

func UpdateStaticInfoAsync() {
	go updateStaticInfo()
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
	si := getStaticInfo()
	if time.Since(start) > 1*time.Second {
		log.Warnf("updateStaticInfo took %s", time.Since(start))
	}

	gio := &Info{
		Kernel:             osInfo[0],
		Platform:           osInfo[2],
		OS:                 osName,
		OSVersion:          osVersion,
		Hostname:           extractDeviceName(ctx, systemHostname),
		GoOS:               runtime.GOOS,
		CPUs:               runtime.NumCPU(),
		NetbirdVersion:     version.NetbirdVersion(),
		UIVersion:          extractUserAgent(ctx),
		KernelVersion:      osInfo[1],
		NetworkAddresses:   addrs,
		SystemSerialNumber: si.SystemSerialNumber,
		SystemProductName:  si.SystemProductName,
		SystemManufacturer: si.SystemManufacturer,
		Environment:        si.Environment,
		DiskEncryption:     detectDiskEncryption(ctx),
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
	si := getSystemInfo()
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

func defaultSysInfoImplementation() SysInfo {
	si := sysinfo.SysInfo{}
	si.GetSysInfo()
	return SysInfo{
		ChassisSerial: si.Chassis.Serial,
		ProductSerial: si.Product.Serial,
		BoardSerial:   si.Board.Serial,
		ProductName:   si.Product.Name,
		BoardName:     si.Board.Name,
		ProductVendor: si.Product.Vendor,
	}
}
