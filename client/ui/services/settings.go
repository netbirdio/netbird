//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

// MDMFields is the shared per-key MDM enforcement snapshot; see mdm.Fields.
type MDMFields = mdm.Fields

// Features is the shared feature-gate snapshot; see mdm.Features.
type Features = mdm.Features

// Restrictions is the shared UI enforcement snapshot; see mdm.Restrictions.
type Restrictions = mdm.Restrictions

// Privilege tells the frontend whether this process may perform the changes the
// daemon restricts to root/administrator, and carries the command for each so a
// disabled control can show the way to do it.
type Privilege struct {
	Privileged bool `json:"privileged"`
	// Actor names what the operation requires ("root", "administrator privileges").
	Actor string `json:"actor"`
	// Commands equivalent to the settings the daemon guards, ready to copy.
	AllowSSHServer string `json:"allowSshServer"`
	EnableSSHRoot  string `json:"enableSshRoot"`
	DisableSSHAuth string `json:"disableSshAuth"`
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
	conn       DaemonConn
	classifier errorClassifier
	// daemonAddr is where the daemon listens, used to tell whether it runs as
	// this user and would therefore authorize us: see Privilege.
	daemonAddr string
}

func NewSettings(conn DaemonConn, translator ErrorTranslator, prefs LanguagePreference, daemonAddr string) *Settings {
	return &Settings{
		conn:       conn,
		classifier: errorClassifier{translator: translator, prefs: prefs},
		daemonAddr: daemonAddr,
	}
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
	if _, err := cli.SetConfig(ctx, req); err != nil {
		// Classified so the frontend gets the daemon's guidance instead of the
		// gRPC envelope, which is what a refused privileged change looks like.
		return s.classifier.classify(err)
	}
	return nil
}

// Privilege reports whether this UI process could carry out the changes the
// daemon restricts to root/administrator, and the command that performs the one
// users hit in the SSH settings. It applies the daemon's own rule to what it can
// see locally, so the frontend can present those controls as unavailable up front
// instead of letting a save fail. No daemon round-trip, so it also works while the
// daemon is down.
//
// Being root or an elevated administrator is one way. The other is running as the
// daemon's own user while the daemon is unprivileged, which the daemon accepts
// because such a caller can already rewrite the config it reads; that is the
// rootless-container and Windows netstack-mode case, and it is read from the
// ownership of the socket or pipe the daemon created.
func (s *Settings) Privilege() Privilege {
	id, err := ipcauth.CurrentProcessIdentity()
	if err != nil {
		// Fail closed: report unprivileged, which only ever disables controls.
		log.Warnf("cannot read this process's identity, treating it as unprivileged: %v", err)
		return newPrivilege(false)
	}
	if id.IsPrivileged() {
		return newPrivilege(true)
	}
	return newPrivilege(daemonaddr.DaemonRunsAsSelf(s.daemonAddr))
}

func newPrivilege(privileged bool) Privilege {
	return Privilege{
		Privileged:     privileged,
		Actor:          ipcauth.PrivilegedActor(),
		AllowSSHServer: ipcauth.UpCommand("--allow-server-ssh"),
		EnableSSHRoot:  ipcauth.UpCommand("--enable-ssh-root"),
		DisableSSHAuth: ipcauth.UpCommand("--disable-ssh-auth"),
	}
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
}
