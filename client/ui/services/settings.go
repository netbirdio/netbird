//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

// ConfigParams selects which profile/user to read or write config for.
type ConfigParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// Config is the daemon configuration the UI exposes in the settings window.
// Pointer fields mark "set" vs "unset" so the UI can omit a value to keep the
// daemon's current setting (matching SetConfigRequest's optional semantics).
type Config struct {
	ManagementURL                 string  `json:"managementUrl"`
	AdminURL                      string  `json:"adminUrl"`
	ConfigFile                    string  `json:"configFile"`
	LogFile                       string  `json:"logFile"`
	PreSharedKey                  string  `json:"preSharedKey"`
	InterfaceName                 string  `json:"interfaceName"`
	WireguardPort                 int64   `json:"wireguardPort"`
	MTU                           int64   `json:"mtu"`
	DisableAutoConnect            bool    `json:"disableAutoConnect"`
	ServerSSHAllowed              bool    `json:"serverSshAllowed"`
	RosenpassEnabled              bool    `json:"rosenpassEnabled"`
	RosenpassPermissive           bool    `json:"rosenpassPermissive"`
	DisableNotifications          bool    `json:"disableNotifications"`
	LazyConnectionEnabled         bool    `json:"lazyConnectionEnabled"`
	BlockInbound                  bool    `json:"blockInbound"`
	NetworkMonitor                bool    `json:"networkMonitor"`
	DisableClientRoutes           bool    `json:"disableClientRoutes"`
	DisableServerRoutes           bool    `json:"disableServerRoutes"`
	DisableDNS                    bool    `json:"disableDns"`
	DisableIPv6                   bool    `json:"disableIpv6"`
	BlockLANAccess                bool    `json:"blockLanAccess"`
	EnableSSHRoot                 bool    `json:"enableSshRoot"`
	EnableSSHSFTP                 bool    `json:"enableSshSftp"`
	EnableSSHLocalPortForwarding  bool    `json:"enableSshLocalPortForwarding"`
	EnableSSHRemotePortForwarding bool    `json:"enableSshRemotePortForwarding"`
	DisableSSHAuth                bool    `json:"disableSshAuth"`
	SSHJWTCacheTTL                int32   `json:"sshJwtCacheTtl"`
}

// SetConfigParams is a partial update — only fields with non-nil pointers
// are sent to the daemon. The frontend uses this to flip individual toggles.
type SetConfigParams struct {
	ProfileName                   string  `json:"profileName"`
	Username                      string  `json:"username"`
	ManagementURL                 string  `json:"managementUrl"`
	AdminURL                      string  `json:"adminUrl"`
	InterfaceName                 *string `json:"interfaceName,omitempty"`
	WireguardPort                 *int64  `json:"wireguardPort,omitempty"`
	MTU                           *int64  `json:"mtu,omitempty"`
	PreSharedKey                  *string `json:"preSharedKey,omitempty"`
	DisableAutoConnect            *bool   `json:"disableAutoConnect,omitempty"`
	ServerSSHAllowed              *bool   `json:"serverSshAllowed,omitempty"`
	RosenpassEnabled              *bool   `json:"rosenpassEnabled,omitempty"`
	RosenpassPermissive           *bool   `json:"rosenpassPermissive,omitempty"`
	DisableNotifications          *bool   `json:"disableNotifications,omitempty"`
	LazyConnectionEnabled         *bool   `json:"lazyConnectionEnabled,omitempty"`
	BlockInbound                  *bool   `json:"blockInbound,omitempty"`
	NetworkMonitor                *bool   `json:"networkMonitor,omitempty"`
	DisableClientRoutes           *bool   `json:"disableClientRoutes,omitempty"`
	DisableServerRoutes           *bool   `json:"disableServerRoutes,omitempty"`
	DisableDNS                    *bool   `json:"disableDns,omitempty"`
	DisableIPv6                   *bool   `json:"disableIpv6,omitempty"`
	DisableFirewall               *bool   `json:"disableFirewall,omitempty"`
	BlockLANAccess                *bool   `json:"blockLanAccess,omitempty"`
	EnableSSHRoot                 *bool   `json:"enableSshRoot,omitempty"`
	EnableSSHSFTP                 *bool   `json:"enableSshSftp,omitempty"`
	EnableSSHLocalPortForwarding  *bool   `json:"enableSshLocalPortForwarding,omitempty"`
	EnableSSHRemotePortForwarding *bool   `json:"enableSshRemotePortForwarding,omitempty"`
	DisableSSHAuth                *bool   `json:"disableSshAuth,omitempty"`
	SSHJWTCacheTTL                *int32  `json:"sshJwtCacheTtl,omitempty"`
}

// Features reports which UI surfaces the daemon has disabled. The Fyne UI uses
// these flags to grey out menu items the operator turned off server-side.
type Features struct {
	DisableProfiles       bool `json:"disableProfiles"`
	DisableUpdateSettings bool `json:"disableUpdateSettings"`
	DisableNetworks       bool `json:"disableNetworks"`
}

// Settings groups the daemon RPCs that read and write the daemon config.
type Settings struct {
	conn DaemonConn
}

func NewSettings(conn DaemonConn) *Settings {
	return &Settings{conn: conn}
}

func (s *Settings) GetConfig(ctx context.Context, p ConfigParams) (Config, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return Config{}, err
	}
	resp, err := cli.GetConfig(ctx, &proto.GetConfigRequest{
		ProfileName: p.ProfileName,
		Username:    p.Username,
	})
	if err != nil {
		return Config{}, err
	}
	return Config{
		ManagementURL:                 resp.GetManagementUrl(),
		AdminURL:                      resp.GetAdminURL(),
		ConfigFile:                    resp.GetConfigFile(),
		LogFile:                       resp.GetLogFile(),
		PreSharedKey:                  resp.GetPreSharedKey(),
		InterfaceName:                 resp.GetInterfaceName(),
		WireguardPort:                 resp.GetWireguardPort(),
		MTU:                           resp.GetMtu(),
		DisableAutoConnect:            resp.GetDisableAutoConnect(),
		ServerSSHAllowed:              resp.GetServerSSHAllowed(),
		RosenpassEnabled:              resp.GetRosenpassEnabled(),
		RosenpassPermissive:           resp.GetRosenpassPermissive(),
		DisableNotifications:          resp.GetDisableNotifications(),
		LazyConnectionEnabled:         resp.GetLazyConnectionEnabled(),
		BlockInbound:                  resp.GetBlockInbound(),
		NetworkMonitor:                resp.GetNetworkMonitor(),
		DisableClientRoutes:           resp.GetDisableClientRoutes(),
		DisableServerRoutes:           resp.GetDisableServerRoutes(),
		DisableDNS:                    resp.GetDisableDns(),
		DisableIPv6:                   resp.GetDisableIpv6(),
		BlockLANAccess:                resp.GetBlockLanAccess(),
		EnableSSHRoot:                 resp.GetEnableSSHRoot(),
		EnableSSHSFTP:                 resp.GetEnableSSHSFTP(),
		EnableSSHLocalPortForwarding:  resp.GetEnableSSHLocalPortForwarding(),
		EnableSSHRemotePortForwarding: resp.GetEnableSSHRemotePortForwarding(),
		DisableSSHAuth:                resp.GetDisableSSHAuth(),
		SSHJWTCacheTTL:                resp.GetSshJWTCacheTTL(),
	}, nil
}

func (s *Settings) SetConfig(ctx context.Context, p SetConfigParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	req := &proto.SetConfigRequest{
		ProfileName:                   p.ProfileName,
		Username:                      p.Username,
		ManagementUrl:                 p.ManagementURL,
		AdminURL:                      p.AdminURL,
		InterfaceName:                 p.InterfaceName,
		WireguardPort:                 p.WireguardPort,
		Mtu:                           p.MTU,
		OptionalPreSharedKey:          p.PreSharedKey,
		DisableAutoConnect:            p.DisableAutoConnect,
		ServerSSHAllowed:              p.ServerSSHAllowed,
		RosenpassEnabled:              p.RosenpassEnabled,
		RosenpassPermissive:           p.RosenpassPermissive,
		DisableNotifications:          p.DisableNotifications,
		LazyConnectionEnabled:         p.LazyConnectionEnabled,
		BlockInbound:                  p.BlockInbound,
		NetworkMonitor:                p.NetworkMonitor,
		DisableClientRoutes:           p.DisableClientRoutes,
		DisableServerRoutes:           p.DisableServerRoutes,
		DisableDns:                    p.DisableDNS,
		DisableIpv6:                   p.DisableIPv6,
		DisableFirewall:               p.DisableFirewall,
		BlockLanAccess:                p.BlockLANAccess,
		EnableSSHRoot:                 p.EnableSSHRoot,
		EnableSSHSFTP:                 p.EnableSSHSFTP,
		EnableSSHLocalPortForwarding:  p.EnableSSHLocalPortForwarding,
		EnableSSHRemotePortForwarding: p.EnableSSHRemotePortForwarding,
		DisableSSHAuth:                p.DisableSSHAuth,
		SshJWTCacheTTL:                p.SSHJWTCacheTTL,
	}
	_, err = cli.SetConfig(ctx, req)
	return err
}

func (s *Settings) GetFeatures(ctx context.Context) (Features, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return Features{}, err
	}
	resp, err := cli.GetFeatures(ctx, &proto.GetFeaturesRequest{})
	if err != nil {
		return Features{}, err
	}
	return Features{
		DisableProfiles:       resp.GetDisableProfiles(),
		DisableUpdateSettings: resp.GetDisableUpdateSettings(),
		DisableNetworks:       resp.GetDisableNetworks(),
	}, nil
}
