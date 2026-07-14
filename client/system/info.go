package system

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

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

	RosenpassEnabled    bool
	RosenpassPermissive bool
	ServerSSHAllowed    bool

	DisableClientRoutes        bool
	DisableServerRoutes        bool
	DisableDNS                 bool
	DisableFirewall            bool
	BlockLANAccess             bool
	BlockInbound               bool
	DisableIPv6                bool
	DisableComponentNetworkMap bool

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
	disableDNS, disableFirewall, blockLANAccess, blockInbound, disableIPv6, disableComponentNetworkMap bool,
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
	i.DisableComponentNetworkMap = disableComponentNetworkMap

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

// removeAddresses drops network addresses whose IP matches any of the given
// addresses, regardless of prefix length. Used to exclude the NetBird overlay
// address, which otherwise churns the meta as the interface comes and goes.
func (i *Info) removeAddresses(ips ...netip.Addr) {
	if len(ips) == 0 {
		return
	}
	filtered := i.NetworkAddresses[:0]
	for _, addr := range i.NetworkAddresses {
		if slices.Contains(ips, addr.NetIP.Addr()) {
			continue
		}
		filtered = append(filtered, addr)
	}
	i.NetworkAddresses = filtered
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
// excludeIPs are dropped from the reported network addresses (e.g. our own
// WireGuard overlay address, which otherwise churns the peer meta).
func GetInfoWithChecks(ctx context.Context, checks []*proto.Checks, excludeIPs ...netip.Addr) (*Info, error) {
	log.Debugf("gathering system information with checks: %d", len(checks))
	processCheckPaths := make([]string, 0)
	for _, check := range checks {
		processCheckPaths = append(processCheckPaths, check.GetFiles()...)
	}

	files, err := checkFileAndProcess(ctx, processCheckPaths)
	if err != nil {
		return nil, err
	}
	log.Debugf("gathering process check information completed")

	info := GetInfo(ctx)
	info.Files = files
	info.removeAddresses(excludeIPs...)

	log.Debugf("all system information gathered successfully")
	return info, nil
}

// GetInfoWithChecksTimeout is GetInfoWithChecks bounded by timeout. Posture-check gathering
// runs uncancellable system calls (process enumeration, os.Stat), so calling it inline can
// block the caller for as long as such a call hangs. It runs in a goroutine instead: if it
// does not return within timeout the caller gets (nil, false) and should proceed with
// degraded behavior rather than block. On a gathering error it falls back to base GetInfo.
//
// The buffered channel lets the abandoned goroutine finish and exit once its blocking call
// returns, so it does not leak beyond the duration of that call.
func GetInfoWithChecksTimeout(ctx context.Context, timeout time.Duration, checks []*proto.Checks, excludeIPs ...netip.Addr) (*Info, bool) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	infoCh := make(chan *Info, 1)
	go func() {
		info, err := GetInfoWithChecks(ctx, checks, excludeIPs...)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warnf("failed to get system info with checks: %v", err)
			info = GetInfo(ctx)
			info.removeAddresses(excludeIPs...)
		}
		infoCh <- info
	}()

	select {
	case info := <-infoCh:
		return info, true
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Warnf("gathering system info with checks timed out after %s", timeout)
		} else {
			// Parent context canceled (e.g. shutdown), not a timeout.
			log.Warnf("gathering system info with checks canceled: %v", ctx.Err())
		}
		return nil, false
	}
}
