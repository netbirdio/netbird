package system

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	"github.com/netbirdio/netbird/version"
)

type Win32_OperatingSystem struct {
	Caption string
}

type Win32_ComputerSystem struct {
	Manufacturer string
}

type Win32_ComputerSystemProduct struct {
	Name string
}

type Win32_BIOS struct {
	SerialNumber string
}

// CachedStaticInfo holds all the static system information that never changes
type CachedStaticInfo struct {
	OSName             string
	OSVersion          string
	KernelVersion      string
	SystemSerialNumber string
	SystemProductName  string
	SystemManufacturer string
	Environment        Environment // Assuming this is from your StaticInfo struct
	GoOS               string
	CPUs               int
	Kernel             string
	Platform           string
}

var (
	cachedStaticInfo *CachedStaticInfo
	staticInfoOnce   sync.Once
)

func init() {
	go initStaticInfo()
}

// initStaticInfo initializes all static system information once
func initStaticInfo() {
	staticInfoOnce.Do(func() {
		log.Debugf("initializing static system information (one-time operation)")
		start := time.Now()

		// Get OS info
		osName, osVersion := getOSNameAndVersion()
		buildVersion := getBuildVersion()

		// Get hardware info
		si := updateStaticInfo()

		cachedStaticInfo = &CachedStaticInfo{
			OSName:             osName,
			OSVersion:          osVersion,
			KernelVersion:      buildVersion,
			SystemSerialNumber: si.SystemSerialNumber,
			SystemProductName:  si.SystemProductName,
			SystemManufacturer: si.SystemManufacturer,
			Environment:        si.Environment,
			GoOS:               runtime.GOOS,
			CPUs:               runtime.NumCPU(),
			Kernel:             "windows",
			Platform:           "unknown",
		}

		log.Debugf("static system information initialized in %s", time.Since(start))
	})
}

// GetInfo retrieves system information (static info cached, dynamic info fresh)
func GetInfo(ctx context.Context) *Info {
	initStaticInfo()
	log.Debugf("gathering dynamic system information")
	start := time.Now()

	// Only gather dynamic information that might change
	log.Debugf("gathering networkAddresses")
	addrs, err := networkAddresses()
	if err != nil {
		log.Warnf("failed to discover network addresses: %s", err)
	}

	log.Debugf("gathering Hostname")
	systemHostname, _ := os.Hostname()

	// Create Info struct using cached static info + fresh dynamic info
	gio := &Info{
		// Static information (cached)
		Kernel:             cachedStaticInfo.Kernel,
		OSVersion:          cachedStaticInfo.OSVersion,
		Platform:           cachedStaticInfo.Platform,
		OS:                 cachedStaticInfo.OSName,
		GoOS:               cachedStaticInfo.GoOS,
		CPUs:               cachedStaticInfo.CPUs,
		KernelVersion:      cachedStaticInfo.KernelVersion,
		SystemSerialNumber: cachedStaticInfo.SystemSerialNumber,
		SystemProductName:  cachedStaticInfo.SystemProductName,
		SystemManufacturer: cachedStaticInfo.SystemManufacturer,
		Environment:        cachedStaticInfo.Environment,

		// Dynamic information (fresh each call)
		NetworkAddresses: addrs,
		Hostname:         extractDeviceName(ctx, systemHostname),
		NetbirdVersion:   version.NetbirdVersion(), // This might change with updates
		UIVersion:        extractUserAgent(ctx),    // This might change
	}

	log.Debugf("dynamic system information gathered in %s", time.Since(start))
	return gio
}

func sysInfo() (serialNumber string, productName string, manufacturer string) {
	var err error
	serialNumber, err = sysNumber()
	if err != nil {
		log.Warnf("failed to get system serial number: %s", err)
	}

	productName, err = sysProductName()
	if err != nil {
		log.Warnf("failed to get system product name: %s", err)
	}

	manufacturer, err = sysManufacturer()
	if err != nil {
		log.Warnf("failed to get system manufacturer: %s", err)
	}

	return serialNumber, productName, manufacturer
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

	if len(split) <= 3 {
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

func sysNumber() (string, error) {
	var dst []Win32_BIOS
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil {
		return "", err
	}
	return dst[0].SerialNumber, nil
}

func sysProductName() (string, error) {
	var dst []Win32_ComputerSystemProduct
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil {
		return "", err
	}
	// `ComputerSystemProduct` could be empty on some virtualized systems
	if len(dst) < 1 {
		return "unknown", nil
	}
	return dst[0].Name, nil
}

func sysManufacturer() (string, error) {
	var dst []Win32_ComputerSystem
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil {
		return "", err
	}
	return dst[0].Manufacturer, nil
}
