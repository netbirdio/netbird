//go:build ios

package NetBirdSDK

import (
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
)

// Preferences export a subset of the internal config for gomobile
type Preferences struct {
	configInput profilemanager.ConfigInput
	mdmLoader   *mdm.Loader
}

// NewPreferences create new Preferences instance
func NewPreferences(configPath string, stateFilePath string) *Preferences {
	ci := profilemanager.ConfigInput{
		ConfigPath:    configPath,
		StateFilePath: stateFilePath,
	}
	return &Preferences{configInput: ci}
}

// SetMDMPolicyFetcher registers the native-provided MDM policy fetcher on
// this Preferences instance; passing nil disables MDM enforcement.
func (p *Preferences) SetMDMPolicyFetcher(f PolicyFetcher) {
	p.mdmLoader = loaderFor(f)
}

// GetRestrictionsJSON returns the UI enforcement snapshot derived from the
// active MDM policy, in the JSON shape shared with the desktop frontend.
func (p *Preferences) GetRestrictionsJSON() (string, error) {
	return mdm.BuildRestrictions(p.policy()).JSON()
}

func (p *Preferences) policy() *mdm.Policy {
	return p.mdmLoader.Load()
}

// GetManagementURL read url from config file
func (p *Preferences) GetManagementURL() (string, error) {
	if v, ok := p.policy().GetString(mdm.KeyManagementURL); ok {
		return mdm.CanonicalURL(v), nil
	}
	if p.configInput.ManagementURL != "" {
		return p.configInput.ManagementURL, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return "", err
	}
	return cfg.ManagementURL.String(), err
}

// SetManagementURL store the given url and wait for commit
func (p *Preferences) SetManagementURL(url string) {
	p.configInput.ManagementURL = url
}

// GetAdminURL read url from config file
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

// SetAdminURL store the given url and wait for commit
func (p *Preferences) SetAdminURL(url string) {
	p.configInput.AdminURL = url
}

// HasPreSharedKey reports whether a pre-shared key is staged, persisted, or
// enforced by MDM; the key itself is never handed to the native layer.
func (p *Preferences) HasPreSharedKey() (bool, error) {
	if _, ok := p.policy().GetString(mdm.KeyPreSharedKey); ok {
		return true, nil
	}
	if p.configInput.PreSharedKey != nil {
		return *p.configInput.PreSharedKey != "", nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.PreSharedKey != "", nil
}

// SetPreSharedKey store the given key and wait for commit
func (p *Preferences) SetPreSharedKey(key string) {
	p.configInput.PreSharedKey = &key
}

// SetRosenpassEnabled store if rosenpass is enabled
func (p *Preferences) SetRosenpassEnabled(enabled bool) {
	p.configInput.RosenpassEnabled = &enabled
}

// GetRosenpassEnabled read rosenpass enabled from config file
func (p *Preferences) GetRosenpassEnabled() (bool, error) {
	if v, ok := p.policy().GetBool(mdm.KeyRosenpassEnabled); ok {
		return v, nil
	}
	if p.configInput.RosenpassEnabled != nil {
		return *p.configInput.RosenpassEnabled, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.RosenpassEnabled, err
}

// SetRosenpassPermissive store the given permissive and wait for commit
func (p *Preferences) SetRosenpassPermissive(permissive bool) {
	p.configInput.RosenpassPermissive = &permissive
}

// GetRosenpassPermissive read rosenpass permissive from config file
func (p *Preferences) GetRosenpassPermissive() (bool, error) {
	if v, ok := p.policy().GetBool(mdm.KeyRosenpassPermissive); ok {
		return v, nil
	}
	if p.configInput.RosenpassPermissive != nil {
		return *p.configInput.RosenpassPermissive, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.RosenpassPermissive, err
}

// GetDisableIPv6 reads disable IPv6 setting from config file
func (p *Preferences) GetDisableIPv6() (bool, error) {
	if p.configInput.DisableIPv6 != nil {
		return *p.configInput.DisableIPv6, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	return cfg.DisableIPv6, err
}

// SetDisableIPv6 stores the given value and waits for commit
func (p *Preferences) SetDisableIPv6(disable bool) {
	p.configInput.DisableIPv6 = &disable
}

// GetRemoteJobsAllowed reads the remote jobs opt-in from config file
func (p *Preferences) GetRemoteJobsAllowed() (bool, error) {
	if p.configInput.RemoteJobsAllowed != nil {
		return *p.configInput.RemoteJobsAllowed, nil
	}

	cfg, err := profilemanager.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return false, err
	}
	if cfg.RemoteJobsAllowed == nil {
		return false, nil
	}
	return *cfg.RemoteJobsAllowed, err
}

// SetRemoteJobsAllowed stores the given value and waits for commit
func (p *Preferences) SetRemoteJobsAllowed(allowed bool) {
	p.configInput.RemoteJobsAllowed = &allowed
}

// Commit write out the changes into config file
func (p *Preferences) Commit() error {
	if err := profilemanager.CheckMDMConflicts(p.configInput, p.policy()); err != nil {
		return err
	}
	// Use DirectUpdateOrCreateConfig to avoid atomic file operations (temp file + rename)
	// which are blocked by the tvOS sandbox in App Group containers
	_, err := profilemanager.DirectUpdateOrCreateConfig(p.configInput)
	return err
}
