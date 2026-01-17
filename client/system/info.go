package system

import (
	"context"
	"net"
	"net/netip"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/management/proto"
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

type File struct {
	Path             string
	Exist            bool
	ProcessIsRunning bool
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
	NetbirdVersion     string
	UIVersion          string
	KernelVersion      string
	NetworkAddresses   []NetworkAddress
	SystemSerialNumber string
	SystemProductName  string
	SystemManufacturer string
	Environment        Environment
	Files              []File // for posture checks
	DiskEncryption     DiskEncryptionInfo

	RosenpassEnabled    bool
	RosenpassPermissive bool
	ServerSSHAllowed    bool

	DisableClientRoutes bool
	DisableServerRoutes bool
	DisableDNS          bool
	DisableFirewall     bool
	BlockLANAccess      bool
	BlockInbound        bool

	LazyConnectionEnabled bool

	EnableSSHRoot                 bool
	EnableSSHSFTP                 bool
	EnableSSHLocalPortForwarding  bool
	EnableSSHRemotePortForwarding bool
	DisableSSHAuth                bool
}

func (i *Info) SetFlags(
	rosenpassEnabled, rosenpassPermissive bool,
	serverSSHAllowed *bool,
	disableClientRoutes, disableServerRoutes,
	disableDNS, disableFirewall, blockLANAccess, blockInbound, lazyConnectionEnabled bool,
	enableSSHRoot, enableSSHSFTP, enableSSHLocalPortForwarding, enableSSHRemotePortForwarding *bool,
	disableSSHAuth *bool,
) {
	i.RosenpassEnabled = rosenpassEnabled
	i.RosenpassPermissive = rosenpassPermissive
	if serverSSHAllowed != nil {
		i.ServerSSHAllowed = *serverSSHAllowed
	}

	i.DisableClientRoutes = disableClientRoutes
	i.DisableServerRoutes = disableServerRoutes
	i.DisableDNS = disableDNS
	i.DisableFirewall = disableFirewall
	i.BlockLANAccess = blockLANAccess
	i.BlockInbound = blockInbound

	i.LazyConnectionEnabled = lazyConnectionEnabled

	if enableSSHRoot != nil {
		i.EnableSSHRoot = *enableSSHRoot
	}
	if enableSSHSFTP != nil {
		i.EnableSSHSFTP = *enableSSHSFTP
	}
	if enableSSHLocalPortForwarding != nil {
		i.EnableSSHLocalPortForwarding = *enableSSHLocalPortForwarding
	}
	if enableSSHRemotePortForwarding != nil {
		i.EnableSSHRemotePortForwarding = *enableSSHRemotePortForwarding
	}
	if disableSSHAuth != nil {
		i.DisableSSHAuth = *disableSSHAuth
	}
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

// GetInfoWithChecks retrieves and parses the system information with applied checks.
func GetInfoWithChecks(ctx context.Context, checks []*proto.Checks) (*Info, error) {
	log.Debugf("gathering system information with checks: %d", len(checks))
	processCheckPaths := make([]string, 0)
	for _, check := range checks {
		processCheckPaths = append(processCheckPaths, check.GetFiles()...)
	}

	files, err := checkFileAndProcess(processCheckPaths)
	if err != nil {
		return nil, err
	}
	log.Debugf("gathering process check information completed")

	info := GetInfo(ctx)
	info.Files = files

	log.Debugf("all system information gathered successfully")
	return info, nil
}
