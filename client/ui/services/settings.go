//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
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

// Privilege tells the frontend whether this process may perform the changes the
// daemon restricts to root/administrator, whether it can ask the operating
// system for the privileges instead, and the command for each so a control that
// can do neither can still show the way.
type Privilege struct {
	Privileged bool `json:"privileged"`
	// ActorKey identifies the principal the operation requires without wording it,
	// so the frontend can name it in the user's language: see
	// ipcauth.PrivilegedActorKey. The words are not sent, because English ones
	// cannot be dropped into a translated sentence.
	ActorKey string `json:"actorKey"`
	// CanElevate reports whether a guarded control can offer to authorize the
	// change through the platform's own prompt: see SetGuardedSettings.
	CanElevate bool `json:"canElevate"`
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
	// elevator raises the platform's privilege prompt when a change needs more
	// rights than this process has.
	elevator elevator
}

func NewSettings(conn DaemonConn, translator ErrorTranslator, prefs LanguagePreference, daemonAddr string) *Settings {
	return &Settings{
		conn:       conn,
		classifier: errorClassifier{translator: translator, prefs: prefs},
		daemonAddr: daemonAddr,
		elevator:   osElevator{},
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

func (s *Settings) SetConfig(ctx context.Context, p SetConfigParams) (SaveOutcome, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return SaveOutcome{}, err
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
		if _, refused := privilegeErrorInfo(err); refused {
			return s.setConfigElevated(ctx, p, req, err)
		}
		// Classified so the frontend gets the daemon's guidance instead of the
		// gRPC envelope.
		return SaveOutcome{}, s.classifier.classify(err)
	}
	return SaveOutcome{}, nil
}

// setConfigElevated answers a request the daemon refused for want of privileges by
// asking the user to authorize it, and sending it again if they do. It is the same
// offer the SSH settings make up front, for the changes a control cannot know are
// guarded until it is told: repointing a profile at another management server is
// only privileged while that host runs the SSH server.
//
// Two steps, because the elevated one-shot deliberately understands only the
// settings the daemon guards: it applies those, and the original request then goes
// through as this user, its privileged parts now asking for nothing that is not
// already stored. Nothing was applied by the refused attempt — the daemon decides
// before it writes — so there is no half-applied state to undo either way.
func (s *Settings) setConfigElevated(ctx context.Context, p SetConfigParams, req *proto.SetConfigRequest, refusal error) (SaveOutcome, error) {
	if !s.canElevate() {
		return SaveOutcome{}, s.classifier.classify(refusal)
	}

	guarded, err := s.guardedChanges(ctx, p)
	if err != nil {
		log.Warnf("cannot tell which guarded settings this request changes: %v", err)
		return SaveOutcome{}, s.classifier.classify(refusal)
	}
	if len(guardedSettings(guarded)) == 0 {
		// Refused over something no prompt can settle, such as a control channel
		// that carries no caller identity. Report the daemon's own guidance.
		return SaveOutcome{}, s.classifier.classify(refusal)
	}

	outcome, err := s.SetGuardedSettings(ctx, guarded)
	if err != nil || outcome.Declined {
		return outcome, err
	}

	cli, err := s.conn.Client()
	if err != nil {
		return SaveOutcome{}, err
	}
	if _, err := cli.SetConfig(ctx, req); err != nil {
		return SaveOutcome{}, s.classifier.classify(err)
	}
	return SaveOutcome{}, nil
}

// guardedChanges is the guarded part of a request, reduced to what it actually
// changes.
//
// A settings form submits every field it holds, so a request restates values the
// daemon already has. Carrying those into the elevated run would spend one
// authorization on more than the user asked for, and a value that has gone stale
// since the form was loaded would spend it on something they never asked about.
func (s *Settings) guardedChanges(ctx context.Context, p SetConfigParams) (GuardedSettings, error) {
	stored, err := s.GetConfig(ctx, ConfigParams{ProfileName: p.ProfileName, Username: p.Username})
	if err != nil {
		return GuardedSettings{}, fmt.Errorf("read the stored config: %w", err)
	}

	guarded := GuardedSettings{
		ProfileName:      p.ProfileName,
		Username:         p.Username,
		ServerSSHAllowed: changedFlag(p.ServerSSHAllowed, stored.ServerSSHAllowed),
		EnableSSHRoot:    changedFlag(p.EnableSSHRoot, stored.EnableSSHRoot),
		DisableSSHAuth:   changedFlag(p.DisableSSHAuth, stored.DisableSSHAuth),
	}
	// An empty URL leaves the setting alone, which is the daemon's rule too.
	if p.ManagementURL != "" && p.ManagementURL != stored.ManagementURL {
		guarded.ManagementURL = p.ManagementURL
	}
	return guarded, nil
}

// Privilege reports whether this UI process could carry out the changes the
// daemon restricts to root/administrator, whether it can instead ask the
// operating system for the privileges when the user wants one of them, and the
// command that performs the ones users hit in the SSH settings. It applies the
// daemon's own rule to what it can see locally, so the frontend can decide up
// front how to present those controls instead of letting a save fail. No daemon
// round-trip, so it also works while the daemon is down.
//
// Being root or an elevated administrator is one way. The other is running as the
// daemon's own user while the daemon is unprivileged, which the daemon accepts
// because such a caller can already rewrite the config it reads; that is the
// rootless-container and Windows netstack-mode case, and it is read from the
// ownership of the socket or pipe the daemon created.
func (s *Settings) Privilege() Privilege {
	id, err := ipcauth.CurrentProcessIdentity()
	if err != nil {
		// Fail closed: report unprivileged, which only ever asks for more.
		log.Warnf("cannot read this process's identity, treating it as unprivileged: %v", err)
		return s.newPrivilege(false)
	}
	if id.IsPrivileged() {
		return s.newPrivilege(true)
	}
	return s.newPrivilege(daemonaddr.DaemonRunsAsSelf(s.daemonAddr))
}

func (s *Settings) newPrivilege(privileged bool) Privilege {
	return Privilege{
		Privileged:     privileged,
		ActorKey:       ipcauth.PrivilegedActorKey(),
		CanElevate:     s.canElevate(),
		AllowSSHServer: ipcauth.UpCommand("--allow-server-ssh"),
		EnableSSHRoot:  ipcauth.UpCommand("--enable-ssh-root"),
		DisableSSHAuth: ipcauth.UpCommand("--disable-ssh-auth"),
	}
}

// canElevate reports whether offering the platform's elevation prompt would get
// the user anywhere. It needs a mechanism to raise the prompt with and a control
// channel that tells the daemon who is calling: on loopback TCP the daemon
// refuses these changes to everybody, root included, so a prompt there would
// only waste the user's password.
func (s *Settings) canElevate() bool {
	if !daemonaddr.CarriesIdentity(s.daemonAddr) {
		log.Debugf("not offering elevation: the daemon address %s carries no caller identity", s.daemonAddr)
		return false
	}
	return s.elevator.Available()
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

// changedFlag returns requested only when it differs from what is stored, so a
// setting the request merely restates is left out of the elevated run.
func changedFlag(requested *bool, stored bool) *bool {
	if requested == nil || *requested == stored {
		return nil
	}
	return requested
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
