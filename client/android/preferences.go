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

// Commit writes out the changes to the config file
func (p *Preferences) Commit() error {
	_, err := profilemanager.UpdateOrCreateConfig(p.configInput)
	return err
}
