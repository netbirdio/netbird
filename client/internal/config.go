package internal

import (
	"fmt"
	"net/url"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/util"
)

const (
	// ManagementLegacyPort is the port that was used before by the Management gRPC server.
	// It is used for backward compatibility now.
	// NB: hardcoded from github.com/netbirdio/netbird/management/cmd to avoid import
	ManagementLegacyPort = 33073
	// DefaultManagementURL points to the NetBird's cloud management endpoint
	DefaultManagementURL = "https://api.wiretrustee.com:443"
	// DefaultAdminURL points to NetBird's cloud management console
	DefaultAdminURL = "https://app.netbird.io:443"
)

var defaultInterfaceBlacklist = []string{iface.WgInterfaceDefault, "wt", "utun", "tun0", "zt", "ZeroTier", "wg", "ts",
	"Tailscale", "tailscale", "docker", "veth", "br-"}

// ConfigInput carries configuration changes to the client
type ConfigInput struct {
	ManagementURL    string
	AdminURL         string
	ConfigPath       string
	PreSharedKey     *string
	NATExternalIPs   []string
	CustomDNSAddress []byte
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
	// CustomDNSAddress sets the DNS resolver listening address in format ip:port
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
		CustomDNSAddress:     string(input.CustomDNSAddress),
	}

	defaultManagementURL, err := ParseURL("Management URL", DefaultManagementURL)
	if err != nil {
		return nil, err
	}

	config.ManagementURL = defaultManagementURL
	if input.ManagementURL != "" {
		URL, err := ParseURL("Management URL", input.ManagementURL)
		if err != nil {
			return nil, err
		}
		config.ManagementURL = URL
	}

	if input.PreSharedKey != nil {
		config.PreSharedKey = *input.PreSharedKey
	}

	defaultAdminURL, err := ParseURL("Admin URL", DefaultAdminURL)
	if err != nil {
		return nil, err
	}

	config.AdminURL = defaultAdminURL
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

// ParseURL parses and validates a service URL
func ParseURL(serviceName, serviceURL string) (*url.URL, error) {
	parsedMgmtURL, err := url.ParseRequestURI(serviceURL)
	if err != nil {
		log.Errorf("failed parsing %s URL %s: [%s]", serviceName, serviceURL, err.Error())
		return nil, err
	}

	if parsedMgmtURL.Scheme != "https" && parsedMgmtURL.Scheme != "http" {
		return nil, fmt.Errorf(
			"invalid %s URL provided %s. Supported format [http|https]://[host]:[port]",
			serviceName, serviceURL)
	}

	if parsedMgmtURL.Port() == "" {
		switch parsedMgmtURL.Scheme {
		case "https":
			parsedMgmtURL.Host = parsedMgmtURL.Host + ":443"
		case "http":
			parsedMgmtURL.Host = parsedMgmtURL.Host + ":80"
		default:
			log.Infof("unable to determine a default port for schema %s in URL %s", parsedMgmtURL.Scheme, serviceURL)
		}
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

	if input.CustomDNSAddress != nil {
		config.CustomDNSAddress = string(input.CustomDNSAddress)
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
	}

	if isPreSharedKeyHidden(input.PreSharedKey) {
		input.PreSharedKey = nil
	}
	return ReadConfig(input)
}

// generateKey generates a new Wireguard private key
func generateKey() string {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	return key.String()
}

// don't overwrite pre-shared key if we receive asterisks from UI
func isPreSharedKeyHidden(preSharedKey *string) bool {
	if preSharedKey != nil && *preSharedKey == "**********" {
		return true
	}
	return false
}
