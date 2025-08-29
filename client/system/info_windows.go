package system

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
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

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	osName, osVersion := getOSNameAndVersion()
	buildVersion := getBuildVersion()

	addrs, err := networkAddresses()
	if err != nil {
		log.Warnf("failed to discover network addresses: %s", err)
	}

	start := time.Now()
	si := updateStaticInfo()
	if time.Since(start) > 1*time.Second {
		log.Warnf("updateStaticInfo took %s", time.Since(start))
	}

	gio := &Info{
		Kernel:             "windows",
		OSVersion:          osVersion,
		Platform:           "unknown",
		OS:                 osName,
		GoOS:               runtime.GOOS,
		CPUs:               runtime.NumCPU(),
		KernelVersion:      buildVersion,
		NetworkAddresses:   addrs,
		SystemSerialNumber: si.SystemSerialNumber,
		SystemProductName:  si.SystemProductName,
		SystemManufacturer: si.SystemManufacturer,
		Environment:        si.Environment,
	}

	systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, systemHostname)
	gio.NetbirdVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

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
