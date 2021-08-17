package internal

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net/url"
	"os"
)

var managementURLDefault *url.URL

func ManagementURLDefault() *url.URL {
	return managementURLDefault
}

func init() {
	managementURL, err := parseManagementURL("https://api.wiretrustee.com:33073")
	if err != nil {
		panic(err)
	}
	managementURLDefault = managementURL
}

// Config Configuration type
type Config struct {
	// Wireguard private key of local peer
	PrivateKey     string
	ManagementURL  *url.URL
	WgIface        string
	IFaceBlackList []string
}

//createNewConfig creates a new config generating a new Wireguard key and saving to file
func createNewConfig(managementURL string, configPath string) (*Config, error) {
	wgKey := generateKey()
	config := &Config{PrivateKey: wgKey, WgIface: iface.WgInterfaceDefault, IFaceBlackList: []string{}}
	if managementURL != "" {
		URL, err := parseManagementURL(managementURL)
		if err != nil {
			return nil, err
		}
		config.ManagementURL = URL
	} else {
		config.ManagementURL = managementURLDefault
	}

	err := util.WriteJson(configPath, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func parseManagementURL(managementURL string) (*url.URL, error) {

	parsedMgmtURL, err := url.ParseRequestURI(managementURL)
	if err != nil {
		log.Errorf("failed parsing management URL %s: [%s]", managementURL, err.Error())
		return nil, err
	}

	if !(parsedMgmtURL.Scheme == "https" || parsedMgmtURL.Scheme == "http") {
		return nil, fmt.Errorf("invalid Management Service URL provided %s. Supported format [http|https]://[host]:[port]", managementURL)
	}

	return parsedMgmtURL, err

}

// ReadConfig reads existing config. In case provided managementURL is not empty overrides the read property
func ReadConfig(managementURL string, configPath string) (*Config, error) {
	config := &Config{}
	_, err := util.ReadJson(configPath, config)
	if err != nil {
		return nil, err
	}

	if managementURL != "" {
		URL, err := parseManagementURL(managementURL)
		if err != nil {
			return nil, err
		}
		config.ManagementURL = URL
	}

	return config, err
}

// GetConfig reads existing config or generates a new one
func GetConfig(managementURL string, configPath string) (*Config, error) {

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Infof("generating new config %s", configPath)
		return createNewConfig(managementURL, configPath)
	} else {
		return ReadConfig(managementURL, configPath)
	}
}

// generateKey generates a new Wireguard private key
func generateKey() string {
	key, err := wgtypes.GenerateKey()
	if err != nil {
		panic(err)
	}
	return key.String()
}
