package internal

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/iface"
	mgm "github.com/netbirdio/netbird/management/client"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ManagementLegacyPort is the port that was used before by the Management gRPC server.
// It is used for backward compatibility now.
// NB: hardcoded from github.com/netbirdio/netbird/management/cmd to avoid import
const ManagementLegacyPort = 33073

var defaultInterfaceBlacklist = []string{iface.WgInterfaceDefault, "wt", "utun", "tun0", "zt", "ZeroTier", "wg", "ts",
	"Tailscale", "tailscale", "docker", "veth", "br-"}

var managementURLDefault *url.URL

func ManagementURLDefault() *url.URL {
	return managementURLDefault
}

func init() {
	managementURL, err := ParseURL("Management URL", "https://api.wiretrustee.com:443")
	if err != nil {
		panic(err)
	}
	managementURLDefault = managementURL
}

// ConfigInput carries configuration changes to the client
type ConfigInput struct {
	ManagementURL       string
	AdminURL            string
	ConfigPath          string
	PreSharedKey        *string
	NATExternalIPs      []string
	DNSListeningAddress string
	CustomDNSAddress    string
}

// Config Configuration type
type Config struct {
	// Wireguard private key of local peer
	PrivateKey           string
	PreSharedKey         string
	ManagementURL        *url.URL
	AdminURL             *url.URL
	WgIface              string
	WgPort               int
	IFaceBlackList       []string
	DisableIPv6Discovery bool
	// SSHKey is a private SSH key in a PEM format
	SSHKey string

	// ExternalIP mappings, if different than the host interface IP
	//
	//   External IP must not be behind a CGNAT and port-forwarding for incoming UDP packets from WgPort on ExternalIP
	//   to WgPort on host interface IP must be present. This can take form of single port-forwarding rule, 1:1 DNAT
	//   mapping ExternalIP to host interface IP, or a NAT DMZ to host interface IP.
	//
	//   A single mapping will take the form of: external[/internal]
	//    external (required): either the external IP address or "stun" to use STUN to determine the external IP address
	//    internal (optional): either the internal/interface IP address or an interface name
	//
	//   examples:
	//      "12.34.56.78"          => all interfaces IPs will be mapped to external IP of 12.34.56.78
	//      "12.34.56.78/eth0"     => IPv4 assigned to interface eth0 will be mapped to external IP of 12.34.56.78
	//      "12.34.56.78/10.1.2.3" => interface IP 10.1.2.3 will be mapped to external IP of 12.34.56.78

	NATExternalIPs []string
	// CustomDNSAddress ip:port string with address for dns resolver to listen to
	CustomDNSAddress string
}

// createNewConfig creates a new config generating a new Wireguard key and saving to file
func createNewConfig(input ConfigInput) (*Config, error) {
	wgKey := generateKey()
	pem, err := ssh.GeneratePrivateKey(ssh.ED25519)
	if err != nil {
		return nil, err
	}
	config := &Config{
		SSHKey:               string(pem),
		PrivateKey:           wgKey,
		WgIface:              iface.WgInterfaceDefault,
		WgPort:               iface.DefaultWgPort,
		IFaceBlackList:       []string{},
		DisableIPv6Discovery: false,
		NATExternalIPs:       input.NATExternalIPs,
		CustomDNSAddress:     input.CustomDNSAddress,
	}
	if input.ManagementURL != "" {
		URL, err := ParseURL("Management URL", input.ManagementURL)
		if err != nil {
			return nil, err
		}
		config.ManagementURL = URL
	} else {
		config.ManagementURL = managementURLDefault
	}

	if input.PreSharedKey != nil {
		config.PreSharedKey = *input.PreSharedKey
	}

	if input.AdminURL != "" {
		newURL, err := ParseURL("Admin Panel URL", input.AdminURL)
		if err != nil {
			return nil, err
		}
		config.AdminURL = newURL
	}

	config.IFaceBlackList = defaultInterfaceBlacklist

	err = util.WriteJson(input.ConfigPath, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// ParseURL parses and validates management URL
func ParseURL(serviceName, managementURL string) (*url.URL, error) {
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

// ReadConfig reads existing configuration and update settings according to input configuration
func ReadConfig(input ConfigInput) (*Config, error) {
	config := &Config{}
	if _, err := os.Stat(input.ConfigPath); os.IsNotExist(err) {
		return nil, status.Errorf(codes.NotFound, "config file doesn't exist")
	}

	if _, err := util.ReadJson(input.ConfigPath, config); err != nil {
		return nil, err
	}

	refresh := false

	if input.ManagementURL != "" && config.ManagementURL.String() != input.ManagementURL {
		log.Infof("new Management URL provided, updated to %s (old value %s)",
			input.ManagementURL, config.ManagementURL)
		newURL, err := ParseURL("Management URL", input.ManagementURL)
		if err != nil {
			return nil, err
		}
		config.ManagementURL = newURL
		refresh = true
	}

	if input.AdminURL != "" && (config.AdminURL == nil || config.AdminURL.String() != input.AdminURL) {
		log.Infof("new Admin Panel URL provided, updated to %s (old value %s)",
			input.AdminURL, config.AdminURL)
		newURL, err := ParseURL("Admin Panel URL", input.AdminURL)
		if err != nil {
			return nil, err
		}
		config.AdminURL = newURL
		refresh = true
	}

	if input.PreSharedKey != nil && config.PreSharedKey != *input.PreSharedKey {
		log.Infof("new pre-shared key provided, updated to %s (old value %s)",
			*input.PreSharedKey, config.PreSharedKey)
		config.PreSharedKey = *input.PreSharedKey
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

	if config.WgPort == 0 {
		config.WgPort = iface.DefaultWgPort
		refresh = true
	}
	if input.NATExternalIPs != nil && len(config.NATExternalIPs) != len(input.NATExternalIPs) {
		config.NATExternalIPs = input.NATExternalIPs
		refresh = true
	}

	if config.CustomDNSAddress != input.CustomDNSAddress {
		config.CustomDNSAddress = input.CustomDNSAddress
		refresh = true
	}

	if refresh {
		// since we have new management URL, we need to update config file
		if err := util.WriteJson(input.ConfigPath, config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

// GetConfig reads existing config or generates a new one
func GetConfig(input ConfigInput) (*Config, error) {
	if _, err := os.Stat(input.ConfigPath); os.IsNotExist(err) {
		log.Infof("generating new config %s", input.ConfigPath)
		return createNewConfig(input)
	} else {
		// don't overwrite pre-shared key if we receive asterisks from UI
		if *input.PreSharedKey == "**********" {
			input.PreSharedKey = nil
		}
		return ReadConfig(input)
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
	// Deprecated. Use OIDCConfigEndpoint instead
	Domain string
	// Audience An Audience for to authorization validation
	Audience string
	// TokenEndpoint is the endpoint of an IDP manager where clients can obtain access token
	TokenEndpoint string
	// DeviceAuthEndpoint is the endpoint of an IDP manager where clients can obtain device authorization code
	DeviceAuthEndpoint string
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
	log.Debugf("connected to the Management service %s", config.ManagementURL.String())
	defer func() {
		err = mgmClient.Close()
		if err != nil {
			log.Warnf("failed to close the Management service client %v", err)
		}
	}()

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

	deviceAuthorizationFlow := DeviceAuthorizationFlow{
		Provider: protoDeviceAuthorizationFlow.Provider.String(),

		ProviderConfig: ProviderConfig{
			Audience:           protoDeviceAuthorizationFlow.GetProviderConfig().GetAudience(),
			ClientID:           protoDeviceAuthorizationFlow.GetProviderConfig().GetClientID(),
			ClientSecret:       protoDeviceAuthorizationFlow.GetProviderConfig().GetClientSecret(),
			Domain:             protoDeviceAuthorizationFlow.GetProviderConfig().Domain,
			TokenEndpoint:      protoDeviceAuthorizationFlow.GetProviderConfig().GetTokenEndpoint(),
			DeviceAuthEndpoint: protoDeviceAuthorizationFlow.GetProviderConfig().GetDeviceAuthEndpoint(),
		},
	}

	err = isProviderConfigValid(deviceAuthorizationFlow.ProviderConfig)
	if err != nil {
		return DeviceAuthorizationFlow{}, err
	}

	return deviceAuthorizationFlow, nil
}

func isProviderConfigValid(config ProviderConfig) error {
	errorMSGFormat := "invalid provider configuration received from management: %s value is empty. Contact your NetBird administrator"
	if config.Audience == "" {
		return fmt.Errorf(errorMSGFormat, "Audience")
	}
	if config.ClientID == "" {
		return fmt.Errorf(errorMSGFormat, "Client ID")
	}
	if config.TokenEndpoint == "" {
		return fmt.Errorf(errorMSGFormat, "Token Endpoint")
	}
	if config.DeviceAuthEndpoint == "" {
		return fmt.Errorf(errorMSGFormat, "Device Auth Endpoint")
	}
	return nil
}
