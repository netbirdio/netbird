package internal

import (
	"fmt"
	"net/url"
	"os"

	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var managementURLDefault *url.URL

func ManagementURLDefault() *url.URL {
	return managementURLDefault
}

func init() {
	managementURL, err := parseURL("Management URL", "https://api.wiretrustee.com:33073")
	if err != nil {
		panic(err)
	}
	managementURLDefault = managementURL
}

// Config Configuration type
type Config struct {
	// Wireguard private key of local peer
	PrivateKey     string
	PreSharedKey   string
	ManagementURL  *url.URL
	AdminURL       *url.URL
	WgIface        string
	IFaceBlackList []string
}

// createNewConfig creates a new config generating a new Wireguard key and saving to file
func createNewConfig(managementURL, adminURL, configPath, preSharedKey string) (*Config, error) {
	wgKey := generateKey()
	config := &Config{PrivateKey: wgKey, WgIface: iface.WgInterfaceDefault, IFaceBlackList: []string{}}
	if managementURL != "" {
		URL, err := parseURL("Management URL", managementURL)
		if err != nil {
			return nil, err
		}
		config.ManagementURL = URL
	} else {
		config.ManagementURL = managementURLDefault
	}

	if preSharedKey != "" {
		config.PreSharedKey = preSharedKey
	}

	config.IFaceBlackList = []string{iface.WgInterfaceDefault, "tun0"}

	err := util.WriteJson(configPath, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func parseURL(serviceName, managementURL string) (*url.URL, error) {
	parsedMgmtURL, err := url.ParseRequestURI(managementURL)
	if err != nil {
		log.Errorf("failed parsing management URL %s: [%s]", managementURL, err.Error())
		return nil, err
	}

	if parsedMgmtURL.Scheme != "https" && parsedMgmtURL.Scheme != "http" {
		return nil, fmt.Errorf(
			"invalid %s URL provided %s. Supported format [http|https]://[host]:[port]",
			serviceName, managementURL)
	}

	return parsedMgmtURL, err
}

// ReadConfig reads existing config. In case provided managementURL is not empty overrides the read property
func ReadConfig(managementURL, adminURL, configPath string, preSharedKey *string) (*Config, error) {
	config := &Config{}
	if _, err := util.ReadJson(configPath, config); err != nil {
		return nil, err
	}

	refresh := false

	if managementURL != "" && config.ManagementURL.String() != managementURL {
		log.Infof("new Management URL provided, updated to %s (old value %s)",
			managementURL, config.ManagementURL)
		newURL, err := parseURL("Management URL", managementURL)
		if err != nil {
			return nil, err
		}
		config.ManagementURL = newURL
		refresh = true
	}

	if adminURL != "" && (config.AdminURL == nil || config.AdminURL.String() != adminURL) {
		log.Infof("new Admin Panel URL provided, updated to %s (old value %s)",
			adminURL, config.AdminURL)
		newURL, err := parseURL("Admin Panel URL", adminURL)
		if err != nil {
			return nil, err
		}
		config.AdminURL = newURL
		refresh = true
	}

	if preSharedKey != nil && config.PreSharedKey != *preSharedKey {
		log.Infof("new pre-shared key provided, updated to %s (old value %s)",
			*preSharedKey, config.PreSharedKey)
		config.PreSharedKey = *preSharedKey
		refresh = true
	}

	if refresh {
		// since we have new management URL, we need to update config file
		if err := util.WriteJson(configPath, config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

// GetConfig reads existing config or generates a new one
func GetConfig(managementURL, adminURL, configPath, preSharedKey string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Infof("generating new config %s", configPath)
		return createNewConfig(managementURL, adminURL, configPath, preSharedKey)
	} else {
		// don't overwrite pre-shared key if we receive asterisks from UI
		pk := &preSharedKey
		if preSharedKey == "**********" {
			pk = nil
		}
		return ReadConfig(managementURL, adminURL, configPath, pk)
	}
}

// generateKey generates a new Wireguard private key
func generateKey() string {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	return key.String()
}
