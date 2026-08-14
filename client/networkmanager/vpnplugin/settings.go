//go:build linux

package vpnplugin

import (
	"fmt"
	"strconv"

	"google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	nbproto "github.com/netbirdio/netbird/client/proto"
)

// vpn.data / vpn.secrets keys understood by this plugin. Kept in sync by
// convention with client/networkmanager/properties/nm-netbird-service-defines.h,
// which the GTK4 editor plugin uses to read/write the same connection.
const (
	keyManagementURL       = "management-url"
	keyAdminURL            = "admin-url"
	keySetupKey            = "setup-key" // secret
	keyInterfaceName       = "interface-name"
	keyHostname            = "hostname"
	keyMTU                 = "mtu"
	keyWireguardPort       = "wireguard-port"
	keyBlockInbound        = "block-inbound"
	keyDisableServerRoutes = "disable-server-routes"
	keyBlockLANAccess      = "block-lan-access"
	keyDisableClientRoutes = "disable-client-routes"
	keyDisableDNS          = "disable-dns"
	keyDisableFirewall     = "disable-firewall"
	keyDisableIPv6         = "disable-ipv6"
	keyRosenpassEnabled    = "rosenpass-enabled"
	keyRosenpassPermissive = "rosenpass-permissive"
	keyDisableAutoConnect  = "disable-auto-connect"
	keyNetworkMonitor      = "network-monitor"

	boolTrue = "yes"
)

// settings is the parsed form of a netbird NM connection's vpn.data/
// vpn.secrets, ready to translate into netbird daemon RPC requests.
type settings struct {
	managementURL string
	adminURL      string
	setupKey      string
	interfaceName string
	hostname      string
	mtu           int64
	wireguardPort int64

	blockInbound        bool
	disableServerRoutes bool
	blockLANAccess      bool
	disableClientRoutes bool
	disableDNS          bool
	disableFirewall     bool
	disableIPv6         bool
	rosenpassEnabled    bool
	rosenpassPermissive bool
	disableAutoConnect  bool
	networkMonitor      bool
}

// parseSettings builds a settings value from a connection's vpn.data and
// vpn.secrets string maps, as delivered by NetworkManager's Connect/
// ConnectInteractive D-Bus calls.
func parseSettings(data, secrets map[string]string) (*settings, error) {
	managementURL := data[keyManagementURL]
	if managementURL == "" {
		managementURL = profilemanager.DefaultManagementURL
	}

	mtu, err := parseOptionalInt(data[keyMTU])
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", keyMTU, err)
	}
	wireguardPort, err := parseOptionalInt(data[keyWireguardPort])
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", keyWireguardPort, err)
	}

	return &settings{
		managementURL: managementURL,
		adminURL:      data[keyAdminURL],
		setupKey:      secrets[keySetupKey],
		interfaceName: data[keyInterfaceName],
		hostname:      data[keyHostname],
		mtu:           mtu,
		wireguardPort: wireguardPort,

		blockInbound:        data[keyBlockInbound] == boolTrue,
		disableServerRoutes: data[keyDisableServerRoutes] == boolTrue,
		blockLANAccess:      data[keyBlockLANAccess] == boolTrue,
		disableClientRoutes: data[keyDisableClientRoutes] == boolTrue,
		disableDNS:          data[keyDisableDNS] == boolTrue,
		disableFirewall:     data[keyDisableFirewall] == boolTrue,
		disableIPv6:         data[keyDisableIPv6] == boolTrue,
		rosenpassEnabled:    data[keyRosenpassEnabled] == boolTrue,
		rosenpassPermissive: data[keyRosenpassPermissive] == boolTrue,
		disableAutoConnect:  data[keyDisableAutoConnect] == boolTrue,
		networkMonitor:      data[keyNetworkMonitor] == boolTrue,
	}, nil
}

func parseOptionalInt(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	return strconv.ParseInt(value, 10, 64)
}

// setConfigRequest builds the SetConfig RPC request for these settings.
func (s *settings) setConfigRequest() *nbproto.SetConfigRequest {
	req := &nbproto.SetConfigRequest{
		ManagementUrl:       s.managementURL,
		AdminURL:            s.adminURL,
		BlockInbound:        proto.Bool(s.blockInbound),
		DisableServerRoutes: proto.Bool(s.disableServerRoutes),
		BlockLanAccess:      proto.Bool(s.blockLANAccess),
		DisableClientRoutes: proto.Bool(s.disableClientRoutes),
		DisableDns:          proto.Bool(s.disableDNS),
		DisableFirewall:     proto.Bool(s.disableFirewall),
		DisableIpv6:         proto.Bool(s.disableIPv6),
		RosenpassEnabled:    proto.Bool(s.rosenpassEnabled),
		RosenpassPermissive: proto.Bool(s.rosenpassPermissive),
		DisableAutoConnect:  proto.Bool(s.disableAutoConnect),
		NetworkMonitor:      proto.Bool(s.networkMonitor),
	}
	if s.interfaceName != "" {
		req.InterfaceName = proto.String(s.interfaceName)
	}
	if s.wireguardPort != 0 {
		req.WireguardPort = proto.Int64(s.wireguardPort)
	}
	if s.mtu != 0 {
		req.Mtu = proto.Int64(s.mtu)
	}
	return req
}

// loginRequest builds the Login RPC request for these settings.
func (s *settings) loginRequest() *nbproto.LoginRequest {
	req := &nbproto.LoginRequest{
		SetupKey:            s.setupKey,
		ManagementUrl:       s.managementURL,
		AdminURL:            s.adminURL,
		Hostname:            s.hostname,
		IsUnixDesktopClient: true,
		BlockInbound:        proto.Bool(s.blockInbound),
		DisableServerRoutes: proto.Bool(s.disableServerRoutes),
		BlockLanAccess:      proto.Bool(s.blockLANAccess),
		DisableClientRoutes: proto.Bool(s.disableClientRoutes),
		DisableDns:          proto.Bool(s.disableDNS),
		DisableFirewall:     proto.Bool(s.disableFirewall),
		DisableIpv6:         proto.Bool(s.disableIPv6),
		RosenpassEnabled:    proto.Bool(s.rosenpassEnabled),
		RosenpassPermissive: proto.Bool(s.rosenpassPermissive),
		DisableAutoConnect:  proto.Bool(s.disableAutoConnect),
		NetworkMonitor:      proto.Bool(s.networkMonitor),
	}
	if s.interfaceName != "" {
		req.InterfaceName = proto.String(s.interfaceName)
	}
	if s.wireguardPort != 0 {
		req.WireguardPort = proto.Int64(s.wireguardPort)
	}
	if s.mtu != 0 {
		req.Mtu = proto.Int64(s.mtu)
	}
	return req
}
