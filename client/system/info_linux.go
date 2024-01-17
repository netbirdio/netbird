//go:build !android
// +build !android

package system

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zcalusic/sysinfo"

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
	for strings.Contains(releaseInfo, "broken pipe") {
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

	sysinfo := extendedInfo()
	localAddr, macAddr := localAddresses()
	gio := &Info{
		Kernel:             osInfo[0],
		Core:               osInfo[1],
		Platform:           osInfo[2],
		OS:                 osName,
		OSVersion:          osVer,
		GoOS:               runtime.GOOS,
		CPUs:               runtime.NumCPU(),
		Hostname:           extractDeviceName(ctx, systemHostname),
		WiretrusteeVersion: version.NetbirdVersion(),
		UIVersion:          extractUserAgent(ctx),
		BiosManufacturer:   sysinfo.BIOS.Vendor,
		BiosVersion:        sysinfo.BIOS.Version,
		ChassisType:        sysinfo.Chassis.Type,
		ChassisTypeDesc:    chassisTypeDesc(sysinfo.Chassis.Type), // make no sense to send the string to the server
		/*
			ConnectionIp:         "",                                    // "10.145.236.123",
			ConnectionMacAddress: "",                                    // 52-54-00-1a-31-05"
			CPUSignature:         "",                                    // "198339"
		*/
		LastReboot: lastReboot(),
		LocalIp:    localAddr,
		MacAddress: macAddr,
		/*
			OSBuild:              string // 22621
			OSProductName:        string // "Windows 11 Home"
			ProductTypeDesc:      string // "Workstation"
			SerialNumber:         string // "MP1PKC2C""
			SystemProductName:    string // "81ND", # how to get this?
		*/
		SystemManufacturer: sysinfo.Product.Vendor, // todo validate
	}
	return gio
}

func extendedInfo() sysinfo.SysInfo {
	var si sysinfo.SysInfo
	si.GetSysInfo()
	return si
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
