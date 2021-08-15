package internal

import (
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
)

const ManagementAddrDefault = "https://app.wiretrustee.com"

// Config Configuration type
type Config struct {
	// Wireguard private key of local peer
	PrivateKey     string
	ManagementURL  string
	WgIface        string
	IFaceBlackList []string
}

//createNewConfig creates a new config generating a new Wireguard key and saving to file
func createNewConfig(managementURL string, configPath string) (*Config, error) {
	wgKey := generateKey()
	config := &Config{PrivateKey: wgKey, WgIface: iface.WgInterfaceDefault, IFaceBlackList: []string{}}
	if managementURL != "" {
		config.ManagementURL = managementURL
	} else {
		config.ManagementURL = ManagementAddrDefault
	}

	err := util.WriteJson(configPath, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// GetConfig reads existing config or generates a new one
func GetConfig(managementURL string, configPath string) (*Config, error) {

	var config *Config
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Warnf("first run - generating new config %s", configPath)
		config, err = createNewConfig(managementURL, configPath)
		if err != nil {
			return nil, err
		}
	} else {
		config = &Config{}
		_, err := util.ReadJson(configPath, config)
		if err != nil {
			return nil, err
		}
	}

	if managementURL != "" {
		config.ManagementURL = managementURL
	}

	return config, nil
}

// generateKey generates a new Wireguard private key
func generateKey() string {
	key, err := wgtypes.GenerateKey()
	if err != nil {
		panic(err)
	}
	return key.String()
}
