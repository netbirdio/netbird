package android

import (
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Preferences exports a subset of the internal config for gomobile
type Preferences struct {
	configInput profilemanager.ConfigInput
}

// NewPreferences creates a new Preferences instance
func NewPreferences(configPath string) *Preferences {
	ci := profilemanager.ConfigInput{
		ConfigPath: configPath,
	}
	return &Preferences{ci}
}

// GetManagementURL reads URL from config file
func (p *Preferences) GetManagementURL() (string, error) {
	if p.configInput.ManagementURL != "" {
		return p.configInput.ManagementURL, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return "", err
	}
	return cfg.ManagementURL.String(), err
}

// SetManagementURL stores the given URL and waits for commit
func (p *Preferences) SetManagementURL(url string) {
	p.configInput.ManagementURL = url
}

// GetAdminURL reads URL from config file
func (p *Preferences) GetAdminURL() (string, error) {
	if p.configInput.AdminURL != "" {
		return p.configInput.AdminURL, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return "", err
	}
	return cfg.AdminURL.String(), err
}

// SetAdminURL stores the given URL and waits for commit
func (p *Preferences) SetAdminURL(url string) {
	p.configInput.AdminURL = url
}

// GetPreSharedKey reads pre-shared key from config file
func (p *Preferences) GetPreSharedKey() (string, error) {
	if p.configInput.PreSharedKey != nil {
		return *p.configInput.PreSharedKey, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return "", err
	}
	return cfg.PreSharedKey, err
}

// SetPreSharedKey stores the given key and waits for commit
func (p *Preferences) SetPreSharedKey(key string) {
	p.configInput.PreSharedKey = &key
}

// SetRosenpassEnabled stores whether Rosenpass is enabled
func (p *Preferences) SetRosenpassEnabled(enabled bool) {
	p.configInput.RosenpassEnabled = &enabled
}

// GetRosenpassEnabled reads Rosenpass enabled status from config file
func (p *Preferences) GetRosenpassEnabled() (bool, error) {
	if p.configInput.RosenpassEnabled != nil {
		return *p.configInput.RosenpassEnabled, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.RosenpassEnabled, err
}

// SetRosenpassPermissive stores the given permissive setting and waits for commit
func (p *Preferences) SetRosenpassPermissive(permissive bool) {
	p.configInput.RosenpassPermissive = &permissive
}

// GetRosenpassPermissive reads Rosenpass permissive setting from config file
func (p *Preferences) GetRosenpassPermissive() (bool, error) {
	if p.configInput.RosenpassPermissive != nil {
		return *p.configInput.RosenpassPermissive, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.RosenpassPermissive, err
}

// GetDisableClientRoutes reads disable client routes setting from config file
func (p *Preferences) GetDisableClientRoutes() (bool, error) {
	if p.configInput.DisableClientRoutes != nil {
		return *p.configInput.DisableClientRoutes, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.DisableClientRoutes, err
}

// SetDisableClientRoutes stores the given value and waits for commit
func (p *Preferences) SetDisableClientRoutes(disable bool) {
	p.configInput.DisableClientRoutes = &disable
}

// GetDisableServerRoutes reads disable server routes setting from config file
func (p *Preferences) GetDisableServerRoutes() (bool, error) {
	if p.configInput.DisableServerRoutes != nil {
		return *p.configInput.DisableServerRoutes, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.DisableServerRoutes, err
}

// SetDisableServerRoutes stores the given value and waits for commit
func (p *Preferences) SetDisableServerRoutes(disable bool) {
	p.configInput.DisableServerRoutes = &disable
}

// GetDisableDNS reads disable DNS setting from config file
func (p *Preferences) GetDisableDNS() (bool, error) {
	if p.configInput.DisableDNS != nil {
		return *p.configInput.DisableDNS, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.DisableDNS, err
}

// SetDisableDNS stores the given value and waits for commit
func (p *Preferences) SetDisableDNS(disable bool) {
	p.configInput.DisableDNS = &disable
}

// GetDisableFirewall reads disable firewall setting from config file
func (p *Preferences) GetDisableFirewall() (bool, error) {
	if p.configInput.DisableFirewall != nil {
		return *p.configInput.DisableFirewall, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.DisableFirewall, err
}

// SetDisableFirewall stores the given value and waits for commit
func (p *Preferences) SetDisableFirewall(disable bool) {
	p.configInput.DisableFirewall = &disable
}

// GetServerSSHAllowed reads server SSH allowed setting from config file
func (p *Preferences) GetServerSSHAllowed() (bool, error) {
	if p.configInput.ServerSSHAllowed != nil {
		return *p.configInput.ServerSSHAllowed, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	if cfg.ServerSSHAllowed == nil {
		// Default to false for security on Android
		return false, nil
	}
	return *cfg.ServerSSHAllowed, err
}

// SetServerSSHAllowed stores the given value and waits for commit
func (p *Preferences) SetServerSSHAllowed(allowed bool) {
	p.configInput.ServerSSHAllowed = &allowed
}

// GetEnableSSHRoot reads SSH root login setting from config file
func (p *Preferences) GetEnableSSHRoot() (bool, error) {
	if p.configInput.EnableSSHRoot != nil {
		return *p.configInput.EnableSSHRoot, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	if cfg.EnableSSHRoot == nil {
		// Default to false for security on Android
		return false, nil
	}
	return *cfg.EnableSSHRoot, err
}

// SetEnableSSHRoot stores the given value and waits for commit
func (p *Preferences) SetEnableSSHRoot(enabled bool) {
	p.configInput.EnableSSHRoot = &enabled
}

// GetEnableSSHSFTP reads SSH SFTP setting from config file
func (p *Preferences) GetEnableSSHSFTP() (bool, error) {
	if p.configInput.EnableSSHSFTP != nil {
		return *p.configInput.EnableSSHSFTP, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	if cfg.EnableSSHSFTP == nil {
		// Default to false for security on Android
		return false, nil
	}
	return *cfg.EnableSSHSFTP, err
}

// SetEnableSSHSFTP stores the given value and waits for commit
func (p *Preferences) SetEnableSSHSFTP(enabled bool) {
	p.configInput.EnableSSHSFTP = &enabled
}

// GetEnableSSHLocalPortForwarding reads SSH local port forwarding setting from config file
func (p *Preferences) GetEnableSSHLocalPortForwarding() (bool, error) {
	if p.configInput.EnableSSHLocalPortForwarding != nil {
		return *p.configInput.EnableSSHLocalPortForwarding, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	if cfg.EnableSSHLocalPortForwarding == nil {
		// Default to false for security on Android
		return false, nil
	}
	return *cfg.EnableSSHLocalPortForwarding, err
}

// SetEnableSSHLocalPortForwarding stores the given value and waits for commit
func (p *Preferences) SetEnableSSHLocalPortForwarding(enabled bool) {
	p.configInput.EnableSSHLocalPortForwarding = &enabled
}

// GetEnableSSHRemotePortForwarding reads SSH remote port forwarding setting from config file
func (p *Preferences) GetEnableSSHRemotePortForwarding() (bool, error) {
	if p.configInput.EnableSSHRemotePortForwarding != nil {
		return *p.configInput.EnableSSHRemotePortForwarding, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	if cfg.EnableSSHRemotePortForwarding == nil {
		// Default to false for security on Android
		return false, nil
	}
	return *cfg.EnableSSHRemotePortForwarding, err
}

// SetEnableSSHRemotePortForwarding stores the given value and waits for commit
func (p *Preferences) SetEnableSSHRemotePortForwarding(enabled bool) {
	p.configInput.EnableSSHRemotePortForwarding = &enabled
}

// GetBlockInbound reads block inbound setting from config file
func (p *Preferences) GetBlockInbound() (bool, error) {
	if p.configInput.BlockInbound != nil {
		return *p.configInput.BlockInbound, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.BlockInbound, err
}

// SetBlockInbound stores the given value and waits for commit
func (p *Preferences) SetBlockInbound(block bool) {
	p.configInput.BlockInbound = &block
}

// GetConnectionMode returns the locally configured connection-mode override
// (canonical lower-kebab-case: "relay-forced", "p2p", "p2p-lazy",
// "p2p-dynamic", "follow-server"), or empty string if no local override
// is configured -- the daemon will then follow the server-pushed value.
func (p *Preferences) GetConnectionMode() (string, error) {
	if p.configInput.ConnectionMode != nil {
		return *p.configInput.ConnectionMode, nil
	}
	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return "", err
	}
	return cfg.ConnectionMode, nil
}

// SetConnectionMode stores a local override for the connection mode.
// Pass an empty string to clear the override (revert to following the
// server-pushed value).
func (p *Preferences) SetConnectionMode(mode string) {
	m := mode
	p.configInput.ConnectionMode = &m
}

// GetRelayTimeoutSeconds returns the locally configured relay-worker
// inactivity timeout in seconds, or 0 if no override is set (follow
// server-pushed value, or built-in default if the server has none).
func (p *Preferences) GetRelayTimeoutSeconds() (int64, error) {
	if p.configInput.RelayTimeoutSeconds != nil {
		return int64(*p.configInput.RelayTimeoutSeconds), nil
	}
	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return 0, err
	}
	return int64(cfg.RelayTimeoutSeconds), nil
}

// SetRelayTimeoutSeconds stores a local override for the relay timeout.
// Pass 0 to clear the override. Negative values are clamped to 0;
// values larger than MaxUint32 are clamped to MaxUint32. The Android
// AdvancedFragment UI already clamps negatives but a Java caller using
// the bare gomobile API directly would otherwise wrap silently.
func (p *Preferences) SetRelayTimeoutSeconds(secs int64) {
	v := clampUint32Seconds(secs)
	p.configInput.RelayTimeoutSeconds = &v
}

// GetP2pTimeoutSeconds returns the locally configured ICE-worker
// inactivity timeout in seconds (only effective in p2p-dynamic mode),
// or 0 if no override is set.
func (p *Preferences) GetP2pTimeoutSeconds() (int64, error) {
	if p.configInput.P2pTimeoutSeconds != nil {
		return int64(*p.configInput.P2pTimeoutSeconds), nil
	}
	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return 0, err
	}
	return int64(cfg.P2pTimeoutSeconds), nil
}

// SetP2pTimeoutSeconds stores a local override for the p2p timeout.
// Pass 0 to clear the override. See SetRelayTimeoutSeconds for clamping.
func (p *Preferences) SetP2pTimeoutSeconds(secs int64) {
	v := clampUint32Seconds(secs)
	p.configInput.P2pTimeoutSeconds = &v
}

// GetP2pRetryMaxSeconds returns the locally configured cap on the
// per-peer ICE-failure backoff schedule, or 0 if no override is set.
func (p *Preferences) GetP2pRetryMaxSeconds() (int64, error) {
	if p.configInput.P2pRetryMaxSeconds != nil {
		return int64(*p.configInput.P2pRetryMaxSeconds), nil
	}
	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return 0, err
	}
	return int64(cfg.P2pRetryMaxSeconds), nil
}

// SetP2pRetryMaxSeconds stores a local override for the backoff cap.
// Pass 0 to clear the override. See SetRelayTimeoutSeconds for clamping.
func (p *Preferences) SetP2pRetryMaxSeconds(secs int64) {
	v := clampUint32Seconds(secs)
	p.configInput.P2pRetryMaxSeconds = &v
}

// clampUint32Seconds maps an int64 seconds value into the uint32 range
// the daemon stores internally. Negative -> 0. >MaxUint32 -> MaxUint32.
// Defensive against Java callers that bypass UI validation.
func clampUint32Seconds(secs int64) uint32 {
	if secs <= 0 {
		return 0
	}
	if secs > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(secs)
}

// Commit writes out the changes to the config file
func (p *Preferences) Commit() error {
	_, err := profilemanager.UpdateOrCreateConfig(p.configInput)
	return err
}
