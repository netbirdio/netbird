package android

import (
	"github.com/netbirdio/netbird/client/internal"
)

// Preferences export a subset of the internal config for gomobile
type Preferences struct {
	configInput internal.ConfigInput
}

// NewPreferences create new Preferences instance
func NewPreferences(configPath string) *Preferences {
	ci := internal.ConfigInput{
		ConfigPath: configPath,
	}
	return &Preferences{ci}
}

// GetManagementURL read url from config file
func (p *Preferences) GetManagementURL() (string, error) {
	if p.configInput.ManagementURL != "" {
		return p.configInput.ManagementURL, nil
	}

	cfg, err := internal.ReadConfig(p.configInput.ConfigPath)
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

	cfg, err := internal.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return "", err
	}
	return cfg.AdminURL.String(), err
}

// SetAdminURL store the given url and wait for commit
func (p *Preferences) SetAdminURL(url string) {
	p.configInput.AdminURL = url
}

// GetPreSharedKey read preshared key from config file
func (p *Preferences) GetPreSharedKey() (string, error) {
	if p.configInput.PreSharedKey != nil {
		return *p.configInput.PreSharedKey, nil
	}

	cfg, err := internal.ReadConfig(p.configInput.ConfigPath)
	if err != nil {
		return "", err
	}
	return cfg.PreSharedKey, err
}

// SetPreSharedKey store the given key and wait for commit
func (p *Preferences) SetPreSharedKey(key string) {
	p.configInput.PreSharedKey = &key
}

// Commit write out the changes into config file
func (p *Preferences) Commit() error {
	_, err := internal.UpdateOrCreateConfig(p.configInput)
	return err
}
