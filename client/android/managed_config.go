package android

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Managed configuration key names for Android Enterprise managed configurations.
// These match the keys defined in app_restrictions.xml on the Android native app side.
const (
	managedConfigKeyManagementURL    = "managementUrl"
	managedConfigKeySetupKey         = "setupKey"
	managedConfigKeyAdminURL         = "adminUrl"
	managedConfigKeyPreSharedKey     = "preSharedKey"
	managedConfigKeyRosenpassEnabled = "rosenpassEnabled"
	managedConfigKeyRosenpassPerm    = "rosenpassPermissive"
	managedConfigKeyDisableAutoConn  = "disableAutoConnect"
)

// Key name getters for the Android Java client to reference the same key constants.

// GetManagedConfigKeyManagementURL returns the key name for management URL
func GetManagedConfigKeyManagementURL() string { return managedConfigKeyManagementURL }

// GetManagedConfigKeySetupKey returns the key name for setup key
func GetManagedConfigKeySetupKey() string { return managedConfigKeySetupKey }

// GetManagedConfigKeyAdminURL returns the key name for admin URL
func GetManagedConfigKeyAdminURL() string { return managedConfigKeyAdminURL }

// GetManagedConfigKeyPreSharedKey returns the key name for pre-shared key
func GetManagedConfigKeyPreSharedKey() string { return managedConfigKeyPreSharedKey }

// GetManagedConfigKeyRosenpassEnabled returns the key name for Rosenpass enabled
func GetManagedConfigKeyRosenpassEnabled() string { return managedConfigKeyRosenpassEnabled }

// GetManagedConfigKeyRosenpassPermissive returns the key name for Rosenpass permissive
func GetManagedConfigKeyRosenpassPermissive() string { return managedConfigKeyRosenpassPerm }

// GetManagedConfigKeyDisableAutoConnect returns the key name for disable auto-connect
func GetManagedConfigKeyDisableAutoConnect() string { return managedConfigKeyDisableAutoConn }

// ManagedConfig holds configuration values pushed by an MDM/EMM via Android Enterprise
// managed configurations (app restrictions). Values set here override user preferences
// on every app launch.
//
// The native Android app reads from RestrictionsManager and populates this struct
// via the setter methods, then calls Apply() to write the values to the config file.
type ManagedConfig struct {
	managementURL    string
	setupKey         string
	adminURL         string
	preSharedKey     *string
	rosenpassEnabled *bool
	rosenpassPerm    *bool
	disableAutoConn  *bool
}

// NewManagedConfig creates a new empty ManagedConfig
func NewManagedConfig() *ManagedConfig {
	return &ManagedConfig{}
}

// SetManagementURL sets the management server URL from MDM config
func (m *ManagedConfig) SetManagementURL(url string) {
	m.managementURL = url
}

// SetSetupKey sets the setup key for silent device registration from MDM config
func (m *ManagedConfig) SetSetupKey(key string) {
	m.setupKey = key
}

// SetAdminURL sets the admin dashboard URL from MDM config
func (m *ManagedConfig) SetAdminURL(url string) {
	m.adminURL = url
}

// SetPreSharedKey sets the WireGuard pre-shared key from MDM config.
// An empty string is treated as absent (no override).
func (m *ManagedConfig) SetPreSharedKey(key string) {
	if key == "" {
		return
	}
	m.preSharedKey = &key
}

// SetRosenpassEnabled sets whether Rosenpass post-quantum encryption is enabled
func (m *ManagedConfig) SetRosenpassEnabled(enabled bool) {
	m.rosenpassEnabled = &enabled
}

// SetRosenpassPermissive sets whether Rosenpass permissive mode is enabled
func (m *ManagedConfig) SetRosenpassPermissive(permissive bool) {
	m.rosenpassPerm = &permissive
}

// SetDisableAutoConnect sets whether auto-connect on launch is disabled
func (m *ManagedConfig) SetDisableAutoConnect(disable bool) {
	m.disableAutoConn = &disable
}

// HasSetupKey returns true if a setup key was provided by MDM
func (m *ManagedConfig) HasSetupKey() bool {
	return m.setupKey != ""
}

// GetSetupKey returns the MDM-provided setup key
func (m *ManagedConfig) GetSetupKey() string {
	return m.setupKey
}

// GetManagementURL returns the MDM-provided management URL
func (m *ManagedConfig) GetManagementURL() string {
	return m.managementURL
}

// HasConfig returns true if any configuration value was set by MDM
func (m *ManagedConfig) HasConfig() bool {
	return m.managementURL != "" ||
		m.setupKey != "" ||
		m.adminURL != "" ||
		m.preSharedKey != nil ||
		m.rosenpassEnabled != nil ||
		m.rosenpassPerm != nil ||
		m.disableAutoConn != nil
}

// hasPersistentConfig returns true if any config value that gets written to
// the config file was set. The setup key is excluded because it is only used
// for registration and is never persisted.
func (m *ManagedConfig) hasPersistentConfig() bool {
	return m.managementURL != "" ||
		m.adminURL != "" ||
		m.preSharedKey != nil ||
		m.rosenpassEnabled != nil ||
		m.rosenpassPerm != nil ||
		m.disableAutoConn != nil
}

// Apply writes the MDM-managed configuration values to the config file at configPath.
// Values provided by MDM override any existing user-set values.
// The setup key is NOT written to the config file — it is used separately for registration.
func (m *ManagedConfig) Apply(configPath string) error {
	if !m.hasPersistentConfig() {
		return nil
	}

	log.Info("Applying MDM managed configuration")

	input := profilemanager.ConfigInput{
		ConfigPath: configPath,
	}

	if m.managementURL != "" {
		input.ManagementURL = m.managementURL
		log.Info("MDM: setting management URL")
	}

	if m.adminURL != "" {
		input.AdminURL = m.adminURL
		log.Info("MDM: setting admin URL")
	}

	if m.preSharedKey != nil {
		input.PreSharedKey = m.preSharedKey
		log.Info("MDM: setting pre-shared key")
	}

	if m.rosenpassEnabled != nil {
		input.RosenpassEnabled = m.rosenpassEnabled
		log.Infof("MDM: setting Rosenpass enabled=%v", *m.rosenpassEnabled)
	}

	if m.rosenpassPerm != nil {
		input.RosenpassPermissive = m.rosenpassPerm
		log.Infof("MDM: setting Rosenpass permissive=%v", *m.rosenpassPerm)
	}

	if m.disableAutoConn != nil {
		input.DisableAutoConnect = m.disableAutoConn
		log.Infof("MDM: setting disable auto-connect=%v", *m.disableAutoConn)
	}

	_, err := profilemanager.UpdateOrCreateConfig(input)
	if err != nil {
		return fmt.Errorf("failed to apply MDM config: %w", err)
	}

	log.Info("MDM managed configuration applied successfully")
	return nil
}
