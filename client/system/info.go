package system

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/version"
)

// DeviceNameCtxKey context key for device name
const DeviceNameCtxKey = "deviceName"

// OsVersionCtxKey context key for operating system version
const OsVersionCtxKey = "OsVersion"

// OsNameCtxKey context key for operating system name
const OsNameCtxKey = "OsName"

// UiVersionCtxKey context key for user UI version
const UiVersionCtxKey = "user-agent"

type NetworkAddress struct {
	NetIP netip.Prefix
	Mac   string
}

type Environment struct {
	Cloud    string
	Platform string
}

// Info is an object that contains machine information
// Most of the code is taken from https://github.com/matishsiao/goInfo
type Info struct {
	GoOS               string
	Kernel             string
	Platform           string
	OS                 string
	OSVersion          string
	Hostname           string
	CPUs               int
	WiretrusteeVersion string
	UIVersion          string
	KernelVersion      string
	NetworkAddresses   []NetworkAddress
	SystemSerialNumber string
	SystemProductName  string
	SystemManufacturer string
	Environment        Environment
	Ipv6Supported      bool
}

// extractUserAgent extracts Netbird's agent (client) name and version from the outgoing context
func extractUserAgent(ctx context.Context) string {
	md, hasMeta := metadata.FromOutgoingContext(ctx)
	if hasMeta {
		agent, ok := md["user-agent"]
		if ok {
			nbAgent := strings.Split(agent[0], " ")[0]
			if strings.HasPrefix(nbAgent, "netbird") {
				return nbAgent
			}
			return ""
		}
	}
	return ""
}

// extractDeviceName extracts device name from context or returns the default system name
func extractDeviceName(ctx context.Context, defaultName string) string {
	v, ok := ctx.Value(DeviceNameCtxKey).(string)
	if !ok {
		return defaultName
	}
	return v
}

// GetDesktopUIUserAgent returns the Desktop ui user agent
func GetDesktopUIUserAgent() string {
	return "netbird-desktop-ui/" + version.NetbirdVersion()
}

func networkAddresses() ([]NetworkAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var netAddresses []NetworkAddress
	for _, iface := range interfaces {
		if iface.HardwareAddr.String() == "" {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, address := range addrs {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}

			if ipNet.IP.IsLoopback() {
				continue
			}

			netAddr := NetworkAddress{
				NetIP: netip.MustParsePrefix(ipNet.String()),
				Mac:   iface.HardwareAddr.String(),
			}

			if isDuplicated(netAddresses, netAddr) {
				continue
			}

			netAddresses = append(netAddresses, netAddr)
		}
	}
	return netAddresses, nil
}

func isDuplicated(addresses []NetworkAddress, addr NetworkAddress) bool {
	for _, duplicated := range addresses {
		if duplicated.NetIP == addr.NetIP {
			return true
		}
	}
	return false
}
