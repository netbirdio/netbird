package internal

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/iface"
	mgm "github.com/netbirdio/netbird/management/client"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/url"
	"os"
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
	// SSHKey is a private SSH key in a PEM format
	SSHKey string
}

// createNewConfig creates a new config generating a new Wireguard key and saving to file
func createNewConfig(managementURL, adminURL, configPath, preSharedKey string) (*Config, error) {
	wgKey := generateKey()
	pem, err := ssh.GeneratePrivateKey(ssh.ED25519)
	if err != nil {
		return nil, err
	}
	config := &Config{SSHKey: string(pem), PrivateKey: wgKey, WgIface: iface.WgInterfaceDefault, IFaceBlackList: []string{}}
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

	config.IFaceBlackList = []string{iface.WgInterfaceDefault, "tun0", "zt", "ZeroTier", "utun", "wg", "ts",
		"Tailscale", "tailscale"}

	err = util.WriteJson(configPath, config)
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
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, status.Errorf(codes.NotFound, "config file doesn't exist")
	}

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
	if config.SSHKey == "" {
		pem, err := ssh.GeneratePrivateKey(ssh.ED25519)
		if err != nil {
			return nil, err
		}
		config.SSHKey = string(pem)
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

// DeviceAuthorizationFlow represents Device Authorization Flow information
type DeviceAuthorizationFlow struct {
	Provider       string
	ProviderConfig ProviderConfig
}

// ProviderConfig has all attributes needed to initiate a device authorization flow
type ProviderConfig struct {
	// ClientID An IDP application client id
	ClientID string
	// ClientSecret An IDP application client secret
	ClientSecret string
	// Domain An IDP API domain
	Domain string
	// Audience An Audience for to authorization validation
	Audience string
}

func GetDeviceAuthorizationFlowInfo(ctx context.Context, config *Config) (DeviceAuthorizationFlow, error) {
	// validate our peer's Wireguard PRIVATE key
	myPrivateKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
		return DeviceAuthorizationFlow{}, err
	}

	var mgmTlsEnabled bool
	if config.ManagementURL.Scheme == "https" {
		mgmTlsEnabled = true
	}

	log.Debugf("connecting to Management Service %s", config.ManagementURL.String())
	mgmClient, err := mgm.NewClient(ctx, config.ManagementURL.Host, myPrivateKey, mgmTlsEnabled)
	if err != nil {
		log.Errorf("failed connecting to Management Service %s %v", config.ManagementURL.String(), err)
		return DeviceAuthorizationFlow{}, err
	}
	log.Debugf("connected to management Service %s", config.ManagementURL.String())

	serverKey, err := mgmClient.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return DeviceAuthorizationFlow{}, err
	}

	protoDeviceAuthorizationFlow, err := mgmClient.GetDeviceAuthorizationFlow(*serverKey)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			log.Warnf("server couldn't find device flow, contact admin: %v", err)
			return DeviceAuthorizationFlow{}, err
		} else {
			log.Errorf("failed to retrieve device flow: %v", err)
			return DeviceAuthorizationFlow{}, err
		}
	}

	err = mgmClient.Close()
	if err != nil {
		log.Errorf("failed closing Management Service client: %v", err)
		return DeviceAuthorizationFlow{}, err
	}

	return DeviceAuthorizationFlow{
		Provider: protoDeviceAuthorizationFlow.Provider.String(),

		ProviderConfig: ProviderConfig{
			Audience:     protoDeviceAuthorizationFlow.ProviderConfig.Audience,
			ClientID:     protoDeviceAuthorizationFlow.ProviderConfig.ClientID,
			ClientSecret: protoDeviceAuthorizationFlow.ProviderConfig.ClientSecret,
			Domain:       protoDeviceAuthorizationFlow.ProviderConfig.Domain,
		},
	}, nil
}
