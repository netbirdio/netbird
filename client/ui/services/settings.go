//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"reflect"

	"github.com/netbirdio/netbird/client/proto"
)

type MDMFields struct {
	ManagementURL            string `json:"managementURL"`
	PreSharedKey             bool   `json:"preSharedKey"`
	WireguardPort            bool   `json:"wireguardPort"`
	RosenpassEnabled         bool   `json:"rosenpassEnabled"`
	RosenpassPermissive      bool   `json:"rosenpassPermissive"`
	DisableClientRoutes      bool   `json:"disableClientRoutes"`
	DisableServerRoutes      bool   `json:"disableServerRoutes"`
	AllowServerSSH           *bool  `json:"allowServerSSH"`
	AllowServerVNC           *bool  `json:"allowServerVNC"`
	DisableVNCApproval       bool   `json:"disableVNCApproval"`
	DisableAutoConnect       bool   `json:"disableAutoConnect"`
	DisableAutostart         bool   `json:"disableAutostart"`
	BlockInbound             bool   `json:"blockInbound"`
	DisableMetricsCollection bool   `json:"disableMetricsCollection"`
	SplitTunnelMode          bool   `json:"splitTunnelMode"`
	SplitTunnelApps          bool   `json:"splitTunnelApps"`
	DisableAdvancedView      bool   `json:"disableAdvancedView"`
}

type Features struct {
	DisableProfiles       bool `json:"disableProfiles"`
	DisableNetworks       bool `json:"disableNetworks"`
	DisableUpdateSettings bool `json:"disableUpdateSettings"`
}

type Restrictions struct {
	MDM      MDMFields `json:"mdm"`
	Features Features  `json:"features"`
}

type ConfigParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

type Config struct {
	ManagementURL                 string `json:"managementUrl"`
	AdminURL                      string `json:"adminUrl"`
	ConfigFile                    string `json:"configFile"`
	LogFile                       string `json:"logFile"`
	PreSharedKeySet               bool   `json:"preSharedKeySet"`
	InterfaceName                 string `json:"interfaceName"`
	WireguardPort                 int64  `json:"wireguardPort"`
	MTU                           int64  `json:"mtu"`
	DisableAutoConnect            bool   `json:"disableAutoConnect"`
	ServerSSHAllowed              bool   `json:"serverSshAllowed"`
	ServerVNCAllowed              bool   `json:"serverVncAllowed"`
	DisableVNCApproval            bool   `json:"disableVncApproval"`
	RosenpassEnabled              bool   `json:"rosenpassEnabled"`
	RosenpassPermissive           bool   `json:"rosenpassPermissive"`
	DisableNotifications          bool   `json:"disableNotifications"`
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
}

// SetConfigParams is a partial update — only non-nil pointer fields are sent
// to the daemon; nil fields are preserved.
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
	ServerVNCAllowed              *bool   `json:"serverVncAllowed,omitempty"`
	DisableVNCApproval            *bool   `json:"disableVncApproval,omitempty"`
	RosenpassEnabled              *bool   `json:"rosenpassEnabled,omitempty"`
	RosenpassPermissive           *bool   `json:"rosenpassPermissive,omitempty"`
	DisableNotifications          *bool   `json:"disableNotifications,omitempty"`
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
		ServerVNCAllowed:              resp.GetServerVNCAllowed(),
		DisableVNCApproval:            resp.GetDisableVNCApproval(),
		RosenpassEnabled:              resp.GetRosenpassEnabled(),
		RosenpassPermissive:           resp.GetRosenpassPermissive(),
		DisableNotifications:          resp.GetDisableNotifications(),
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
		ServerVNCAllowed:              p.ServerVNCAllowed,
		DisableVNCApproval:            p.DisableVNCApproval,
		RosenpassEnabled:              p.RosenpassEnabled,
		RosenpassPermissive:           p.RosenpassPermissive,
		DisableNotifications:          p.DisableNotifications,
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

func (s *Settings) GetRestrictions(ctx context.Context) (Restrictions, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return Restrictions{}, err
	}
	active, err := cli.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil {
		return Restrictions{}, fmt.Errorf("get active profile: %w", err)
	}
	cfgResp, err := cli.GetConfig(ctx, &proto.GetConfigRequest{
		ProfileName: active.GetId(),
		Username:    active.GetUsername(),
	})
	if err != nil {
		return Restrictions{}, err
	}
	featResp, err := cli.GetFeatures(ctx, &proto.GetFeaturesRequest{})
	if err != nil {
		return Restrictions{}, err
	}
	r := Restrictions{
		Features: Features{
			DisableProfiles:       featResp.GetDisableProfiles(),
			DisableNetworks:       featResp.GetDisableNetworks(),
			DisableUpdateSettings: featResp.GetDisableUpdateSettings(),
		},
	}
	applyMDMRestrictions(&r.MDM, cfgResp)
	r.MDM.DisableAdvancedView = featResp.GetDisableAdvancedView()
	return r, nil
}

func applyMDMRestrictions(mdm *MDMFields, cfgResp *proto.GetConfigResponse) {
	managed := cfgResp.GetMDMManagedFields()
	if len(managed) == 0 {
		return
	}
	set := make(map[string]struct{}, len(managed))
	for _, k := range managed {
		set[k] = struct{}{}
	}
	v := reflect.ValueOf(mdm).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if v.Field(i).Kind() != reflect.Bool {
			continue
		}
		if t.Field(i).Name == "DisableAdvancedView" {
			continue
		}
		if _, ok := set[t.Field(i).Tag.Get("json")]; ok {
			v.Field(i).SetBool(true)
		}
	}
	if _, ok := set["managementURL"]; ok {
		mdm.ManagementURL = cfgResp.GetManagementUrl()
	}
	if _, ok := set["allowServerSSH"]; ok {
		allowed := cfgResp.GetServerSSHAllowed()
		mdm.AllowServerSSH = &allowed
	}
	if _, ok := set["allowServerVNC"]; ok {
		allowed := cfgResp.GetServerVNCAllowed()
		mdm.AllowServerVNC = &allowed
	}
}
