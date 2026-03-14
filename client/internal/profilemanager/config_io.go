package profilemanager

import (
	"context"
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/util"
)

// UpdateConfig update existing configuration according to input configuration and return with the configuration
func UpdateConfig(input ConfigInput) (*Config, error) {
	configExists, err := fileExists(input.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to check if config file exists: %w", err)
	}
	if !configExists {
		return nil, fmt.Errorf("config file %s does not exist", input.ConfigPath)
	}

	return update(input)
}

// UpdateOrCreateConfig reads existing config or generates a new one
func UpdateOrCreateConfig(input ConfigInput) (*Config, error) {
	configExists, err := fileExists(input.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to check if config file exists: %w", err)
	}
	if !configExists {
		log.Infof("generating new config %s", input.ConfigPath)
		cfg, err := createNewConfig(input)
		if err != nil {
			return nil, err
		}
		err = util.WriteJsonWithRestrictedPermission(context.Background(), input.ConfigPath, cfg)
		return cfg, err
	}

	if isPreSharedKeyHidden(input.PreSharedKey) {
		input.PreSharedKey = nil
	}
	err = util.EnforcePermission(input.ConfigPath)
	if err != nil {
		log.Errorf("failed to enforce permission on config dir: %v", err)
	}
	return update(input)
}

func update(input ConfigInput) (*Config, error) {
	config := &Config{}

	if _, err := util.ReadJson(input.ConfigPath, config); err != nil {
		return nil, err
	}

	updated, err := config.apply(input)
	if err != nil {
		return nil, err
	}

	if updated {
		if err := util.WriteJson(context.Background(), input.ConfigPath, config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

// GetConfig read config file and return with Config and if it was created. Errors out if it does not exist
func GetConfig(configPath string) (*Config, error) {
	return readConfig(configPath, false)
}

// UpdateOldManagementURL checks whether client can switch to the new Management URL with port 443 and the management domain.
// If it can switch, then it updates the config and returns a new one. Otherwise, it returns the provided config.
// The check is performed only for the NetBird's managed version.
func UpdateOldManagementURL(ctx context.Context, config *Config, configPath string) (*Config, error) {
	defaultManagementURL, err := parseURL("Management URL", DefaultManagementURL)
	if err != nil {
		return nil, err
	}

	parsedOldDefaultManagementURL, err := parseURL("Management URL", oldDefaultManagementURL)
	if err != nil {
		return nil, err
	}

	if config.ManagementURL.Hostname() != defaultManagementURL.Hostname() &&
		config.ManagementURL.Hostname() != parsedOldDefaultManagementURL.Hostname() {
		// only do the check for the NetBird's managed version
		return config, nil
	}

	var mgmTlsEnabled bool
	if config.ManagementURL.Scheme == "https" {
		mgmTlsEnabled = true
	}

	if !mgmTlsEnabled {
		// only do the check for HTTPs scheme (the hosted version of the Management service is always HTTPs)
		return config, nil
	}

	if config.ManagementURL.Port() != managementLegacyPortString &&
		config.ManagementURL.Hostname() == defaultManagementURL.Hostname() {
		return config, nil
	}

	newURL, err := parseURL("Management URL", fmt.Sprintf("%s://%s:%d",
		config.ManagementURL.Scheme, defaultManagementURL.Hostname(), 443))
	if err != nil {
		return nil, err
	}
	// here we check whether we could switch from the legacy 33073 port to the new 443
	log.Infof("attempting to switch from the legacy Management URL %s to the new one %s",
		config.ManagementURL.String(), newURL.String())
	key, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		log.Infof("couldn't switch to the new Management %s", newURL.String())
		return config, err
	}

	client, err := mgm.NewClient(ctx, newURL.Host, key, mgmTlsEnabled)
	if err != nil {
		log.Infof("couldn't switch to the new Management %s", newURL.String())
		return config, err
	}
	defer func() {
		err = client.Close()
		if err != nil {
			log.Warnf("failed to close the Management service client %v", err)
		}
	}()

	// gRPC check
	_, err = client.GetServerPublicKey()
	if err != nil {
		log.Infof("couldn't switch to the new Management %s", newURL.String())
		return nil, err
	}

	// everything is alright => update the config
	newConfig, err := UpdateConfig(ConfigInput{
		ManagementURL: newURL.String(),
		ConfigPath:    configPath,
	})
	if err != nil {
		log.Infof("couldn't switch to the new Management %s", newURL.String())
		return config, fmt.Errorf("failed updating config file: %v", err)
	}
	log.Infof("successfully switched to the new Management URL: %s", newURL.String())

	return newConfig, nil
}

// CreateInMemoryConfig generate a new config but do not write out it to the store
func CreateInMemoryConfig(input ConfigInput) (*Config, error) {
	return createNewConfig(input)
}

// ReadConfig read config file and return with Config. If it is not exists create a new with default values
func ReadConfig(configPath string) (*Config, error) {
	return readConfig(configPath, true)
}

// readConfig read config file and return with Config. If it is not exists create a new with default values
func readConfig(configPath string, createIfMissing bool) (*Config, error) {
	configExists, err := fileExists(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to check if config file exists: %w", err)
	}

	if configExists {
		err := util.EnforcePermission(configPath)
		if err != nil {
			log.Errorf("failed to enforce permission on config dir: %v", err)
		}

		config := &Config{}
		if _, err := util.ReadJson(configPath, config); err != nil {
			return nil, err
		}
		// initialize through apply() without changes
		if changed, err := config.apply(ConfigInput{}); err != nil {
			return nil, err
		} else if changed {
			if err = WriteOutConfig(configPath, config); err != nil {
				return nil, err
			}
		}

		return config, nil
	} else if !createIfMissing {
		return nil, fmt.Errorf("config file %s does not exist", configPath)
	}

	cfg, err := createNewConfig(ConfigInput{ConfigPath: configPath})
	if err != nil {
		return nil, err
	}

	err = WriteOutConfig(configPath, cfg)
	return cfg, err
}

// WriteOutConfig write put the prepared config to the given path
func WriteOutConfig(path string, config *Config) error {
	return util.WriteJson(context.Background(), path, config)
}

// DirectWriteOutConfig writes config directly without atomic temp file operations.
// Use this on platforms where atomic writes are blocked (e.g., tvOS sandbox).
func DirectWriteOutConfig(path string, config *Config) error {
	return util.DirectWriteJson(context.Background(), path, config)
}

// DirectUpdateOrCreateConfig is like UpdateOrCreateConfig but uses direct (non-atomic) writes.
// Use this on platforms where atomic writes are blocked (e.g., tvOS sandbox).
func DirectUpdateOrCreateConfig(input ConfigInput) (*Config, error) {
	configExists, err := fileExists(input.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to check if config file exists: %w", err)
	}
	if !configExists {
		log.Infof("generating new config %s", input.ConfigPath)
		cfg, err := createNewConfig(input)
		if err != nil {
			return nil, err
		}
		err = util.DirectWriteJson(context.Background(), input.ConfigPath, cfg)
		return cfg, err
	}

	if isPreSharedKeyHidden(input.PreSharedKey) {
		input.PreSharedKey = nil
	}

	// Enforce permissions on existing config files (same as UpdateOrCreateConfig)
	if err := util.EnforcePermission(input.ConfigPath); err != nil {
		log.Errorf("failed to enforce permission on config file: %v", err)
	}

	return directUpdate(input)
}

func directUpdate(input ConfigInput) (*Config, error) {
	config := &Config{}

	if _, err := util.ReadJson(input.ConfigPath, config); err != nil {
		return nil, err
	}

	updated, err := config.apply(input)
	if err != nil {
		return nil, err
	}

	if updated {
		if err := util.DirectWriteJson(context.Background(), input.ConfigPath, config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

// ConfigToJSON serializes a Config struct to a JSON string.
// This is useful for exporting config to alternative storage mechanisms
// (e.g., UserDefaults on tvOS where file writes are blocked).
func ConfigToJSON(config *Config) (string, error) {
	bs, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return "", err
	}
	return string(bs), nil
}

// ConfigFromJSON deserializes a JSON string to a Config struct.
// This is useful for restoring config from alternative storage mechanisms.
// After unmarshaling, defaults are applied to ensure the config is fully initialized.
func ConfigFromJSON(jsonStr string) (*Config, error) {
	config := &Config{}
	err := json.Unmarshal([]byte(jsonStr), config)
	if err != nil {
		return nil, err
	}

	// Apply defaults to ensure required fields are initialized.
	// This mirrors what readConfig does after loading from file.
	if _, err := config.apply(ConfigInput{}); err != nil {
		return nil, fmt.Errorf("failed to apply defaults to config: %w", err)
	}

	return config, nil
}