//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

// mdmKeyToConfigField maps an MDM policy key (mdm.Key*) to the JSON field name
// of the matching Config field, so GetConfig can translate the daemon's key
// names to the frontend's field names in exactly one place. Mirrors the
// conflict set the daemon enforces on SetConfig/Login (mdmManagedFieldConflicts);
// keys with no settings field are absent.
var mdmKeyToConfigField = map[string]string{
	mdm.KeyManagementURL:       "managementUrl",
	mdm.KeyPreSharedKey:        "preSharedKey",
	mdm.KeyWireguardPort:       "wireguardPort",
	mdm.KeyRosenpassEnabled:    "rosenpassEnabled",
	mdm.KeyRosenpassPermissive: "rosenpassPermissive",
	mdm.KeyDisableClientRoutes: "disableClientRoutes",
	mdm.KeyDisableServerRoutes: "disableServerRoutes",
	mdm.KeyAllowServerSSH:      "serverSshAllowed",
	mdm.KeyDisableAutoConnect:  "disableAutoConnect",
	mdm.KeyBlockInbound:        "blockInbound",
}

// ConfigParams selects which profile/user to read or write config for.
type ConfigParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// Config is the daemon configuration the UI exposes in the settings window.
// Pointer fields mark "set" vs "unset" so the UI can omit a value to keep the
// daemon's current setting (matching SetConfigRequest's optional semantics).
type Config struct {
	ManagementURL string `json:"managementUrl"`
	AdminURL      string `json:"adminUrl"`
	ConfigFile    string `json:"configFile"`
	LogFile       string `json:"logFile"`
	// PreSharedKeySet reports whether a pre-shared key is configured, without
	// exposing its value (the daemon redacts the PSK). The settings form shows
	// its own "configured" / "managed by MDM" placeholder when true and sends a
	// new PSK only when the user actually types one — the redaction sentinel
	// never crosses to the UI.
	PreSharedKeySet               bool   `json:"preSharedKeySet"`
	InterfaceName                 string `json:"interfaceName"`
	WireguardPort                 int64  `json:"wireguardPort"`
	MTU                           int64  `json:"mtu"`
	DisableAutoConnect            bool   `json:"disableAutoConnect"`
	ServerSSHAllowed              bool   `json:"serverSshAllowed"`
	RosenpassEnabled              bool   `json:"rosenpassEnabled"`
	RosenpassPermissive           bool   `json:"rosenpassPermissive"`
	DisableNotifications          bool   `json:"disableNotifications"`
	LazyConnectionEnabled         bool   `json:"lazyConnectionEnabled"`
	BlockInbound                  bool   `json:"blockInbound"`
	NetworkMonitor                bool   `json:"networkMonitor"`
	DisableClientRoutes           bool   `json:"disableClientRoutes"`
	DisableServerRoutes           bool   `json:"disableServerRoutes"`
	DisableDNS                    bool   `json:"disableDns"`
	DisableIPv6                   bool   `json:"disableIpv6"`
	BlockLANAccess                bool   `json:"blockLanAccess"`
	EnableSSHRoot                 bool   `json:"enableSshRoot"`
	EnableSSHSFTP                 bool   `json:"enableSshSftp"`
	EnableSSHLocalPortForwarding  bool   `json:"enableSshLocalPortForwarding"`
	EnableSSHRemotePortForwarding bool   `json:"enableSshRemotePortForwarding"`
	DisableSSHAuth                bool   `json:"disableSshAuth"`
	SSHJWTCacheTTL                int32  `json:"sshJwtCacheTtl"`
	// MDMManagedFields is the raw list of MDM-managed policy keys exactly as
	// the daemon reports them (mdm.Key* names, e.g. "managementURL",
	// "preSharedKey", "splitTunnelMode"). Includes keys with no settings
	// field (split-tunnel, metrics, the Disable* feature flags). The faithful
	// full set; prefer ManagedFields for per-field gating.
	MDMManagedFields []string `json:"mdmManagedFields"`
	// ManagedFields is the MDM-managed set normalised to Config JSON field
	// names (e.g. "managementUrl", "serverSshAllowed", "preSharedKey"), so the
	// settings form can gate a control with managedFields[fieldName] without
	// translating the daemon's mdm.Key* names. Only managed fields are present
	// (value true); keys with no settings field are omitted (the Disable*
	// feature flags come via GetFeatures instead).
	ManagedFields map[string]bool `json:"managedFields"`
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
		PreSharedKeySet:               resp.GetPreSharedKey() != "",
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
		MDMManagedFields:              resp.GetMDMManagedFields(),
		ManagedFields:                 configManagedFields(resp.GetMDMManagedFields()),
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

// configManagedFields normalises the daemon's MDM-managed key list (mdm.Key*
// names) to a set keyed by Config JSON field names, so the settings form can
// look up a field's locked state directly. Returns a non-nil (possibly empty)
// map so it marshals to {} rather than null.
func configManagedFields(managed []string) map[string]bool {
	out := make(map[string]bool, len(managed))
	for _, k := range managed {
		if field, ok := mdmKeyToConfigField[k]; ok {
			out[field] = true
		}
	}
	return out
}
