package system

import (
	"context"
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

// IFaceDiscoverCtxKey context key for an external network interface
// discoverer (used on mobile platforms where net.Interfaces() is broken).
// The value must implement the same string-format contract as
// stdnet.ExternalIFaceDiscover, but to avoid an import cycle we accept a
// minimal interface here and let the caller adapt.
const IFaceDiscoverCtxKey = "iFaceDiscover"

// IFaceDiscoverFunc is a callback that returns the same newline-separated
// interface description string used by stdnet.ExternalIFaceDiscover.IFaces().
// Each line has the format:
//
//	name index mtu up broadcast loopback pointToPoint multicast|addr1 addr2 ...
type IFaceDiscoverFunc func() (string, error)

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

	RosenpassEnabled    bool
	RosenpassPermissive bool
	ServerSSHAllowed    bool

	DisableClientRoutes bool
	DisableServerRoutes bool
	DisableDNS          bool
	DisableFirewall     bool
	BlockLANAccess      bool
	BlockInbound        bool
	DisableIPv6         bool

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
	disableDNS, disableFirewall, blockLANAccess, blockInbound, disableIPv6, lazyConnectionEnabled bool,
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
	i.DisableIPv6 = disableIPv6

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
