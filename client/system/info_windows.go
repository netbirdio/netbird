package system

import (
	"context"
	"os"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

func UpdateStaticInfoAsync() {
	go updateStaticInfo()
}

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	start := time.Now()
	si := getStaticInfo()
	if time.Since(start) > 1*time.Second {
		log.Warnf("updateStaticInfo took %s", time.Since(start))
	}

	gio := &Info{
		Kernel:             "windows",
		OSVersion:          si.OSVersion,
		Platform:           "unknown",
		OS:                 si.OSName,
		GoOS:               runtime.GOOS,
		CPUs:               runtime.NumCPU(),
		KernelVersion:      si.BuildVersion,
		SystemSerialNumber: si.SystemSerialNumber,
		SystemProductName:  si.SystemProductName,
		SystemManufacturer: si.SystemManufacturer,
		Environment:        si.Environment,
		DiskEncryption:     detectDiskEncryption(ctx),
	}

	addrs, err := networkAddresses()
	if err != nil {
		log.Warnf("failed to discover network addresses: %s", err)
	} else {
		gio.NetworkAddresses = addrs
	}

	systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, systemHostname)
	gio.NetbirdVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)
	return gio
}
