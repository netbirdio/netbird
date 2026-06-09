package system

import (
	"context"
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

// UpdateStaticInfoAsync is a no-op on iOS as there is no static info to update
func UpdateStaticInfoAsync() {
	// do nothing
}

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {

	sysName := extractOsName(ctx, "sysName")
	swVersion := extractOsVersion(ctx, "swVersion")

	addrs, err := networkAddresses()
	if err != nil {
		log.Warnf("failed to discover network addresses: %s", err)
	}

	gio := &Info{
		Kernel:           sysName,
		OSVersion:        swVersion,
		Platform:         "unknown",
		OS:               sysName,
		GoOS:             runtime.GOOS,
		CPUs:             runtime.NumCPU(),
		KernelVersion:    swVersion,
		NetworkAddresses: addrs,
	}
	gio.Hostname = extractDeviceName(ctx, "hostname")
	gio.NetbirdVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

// NetworkAddresses returns the current set of non-loopback network addresses.
// On iOS the system does not expose an external interface discoverer, so the
// context is unused.
func NetworkAddresses(_ context.Context) ([]NetworkAddress, error) {
	return networkAddresses()
}

// networkAddresses returns the list of network addresses on iOS.
// On iOS, hardware (MAC) addresses are not available due to Apple's privacy
// restrictions (iOS returns a fixed 02:00:00:00:00:00 placeholder), so we
// leave Mac empty to match Android's behavior. We also skip the HardwareAddr
// check that other platforms use and filter out link-local addresses as they
// are not useful for posture checks.
func networkAddresses() ([]NetworkAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var netAddresses []NetworkAddress
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, address := range addrs {
			netAddr, ok := toNetworkAddress(address)
			if !ok {
				continue
			}
			if isDuplicated(netAddresses, netAddr) {
				continue
			}
			netAddresses = append(netAddresses, netAddr)
		}
	}
	return netAddresses, nil
}

func toNetworkAddress(address net.Addr) (NetworkAddress, bool) {
	ipNet, ok := address.(*net.IPNet)
	if !ok {
		return NetworkAddress{}, false
	}
	if ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() || ipNet.IP.IsMulticast() {
		return NetworkAddress{}, false
	}
	prefix, err := netip.ParsePrefix(ipNet.String())
	if err != nil {
		return NetworkAddress{}, false
	}
	return NetworkAddress{NetIP: prefix, Mac: ""}, true
}

func isDuplicated(addresses []NetworkAddress, addr NetworkAddress) bool {
	for _, duplicated := range addresses {
		if duplicated.NetIP == addr.NetIP {
			return true
		}
	}
	return false
}

// checkFileAndProcess checks if the file path exists and if a process is running at that path.
func checkFileAndProcess(paths []string) ([]File, error) {
	return []File{}, nil
}

// extractOsVersion extracts operating system version from context or returns the default
func extractOsVersion(ctx context.Context, defaultName string) string {
	v, ok := ctx.Value(OsVersionCtxKey).(string)
	if !ok {
		return defaultName
	}
	return v
}

// extractOsName extracts operating system name from context or returns the default
func extractOsName(ctx context.Context, defaultName string) string {
	v, ok := ctx.Value(OsNameCtxKey).(string)
	if !ok {
		return defaultName
	}
	return v
}
