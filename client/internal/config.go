package internal

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/iface"
	mgm "github.com/netbirdio/netbird/management/client"
	"github.com/netbirdio/netbird/util"
)

const (
	// managementLegacyPortString is the port that was used before by the Management gRPC server.
	// It is used for backward compatibility now.
	// NB: hardcoded from github.com/netbirdio/netbird/management/cmd to avoid import
	managementLegacyPortString = "33073"
	// DefaultManagementURL points to the NetBird's cloud management endpoint
	DefaultManagementURL = "https://api.netbird.io:443"
	// oldDefaultManagementURL points to the NetBird's old cloud management endpoint
	oldDefaultManagementURL = "https://api.wiretrustee.com:443"
	// DefaultAdminURL points to NetBird's cloud management console
	DefaultAdminURL = "https://app.netbird.io:443"
)

var defaultInterfaceBlacklist = []string{
	iface.WgInterfaceDefault, "wt", "utun", "tun0", "zt", "ZeroTier", "wg", "ts",
	"Tailscale", "tailscale", "docker", "veth", "br-", "lo",
}

// ConfigInput carries configuration changes to the client
type ConfigInput struct {
	ManagementURL       string
	AdminURL            string
	ConfigPath          string
	PreSharedKey        *string
	ServerSSHAllowed    *bool
	NATExternalIPs      []string
	CustomDNSAddress    []byte
	RosenpassEnabled    *bool
	RosenpassPermissive *bool
	InterfaceName       *string
	WireguardPort       *int
	NetworkMonitor      *bool
	DisableAutoConnect  *bool
	ExtraIFaceBlackList []string
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
	NetworkMonitor       bool
	IFaceBlackList       []string
	DisableIPv6Discovery bool
	RosenpassEnabled     bool
	RosenpassPermissive  bool
	ServerSSHAllowed     *bool
	// SSHKey is a private SSH key in a PEM format
	SSHKey string

	// ExternalIP mappings, if different from the host interface IP
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

	// DisableAutoConnect determines whether the client should not start with the service
	// it's set to false by default due to backwards compatibility
	DisableAutoConnect bool
}

// ReadConfig read config file and return with Config. If it is not exists create a new with default values
func ReadConfig(configPath string) (*Config, error) {
	if configFileIsExists(configPath) {
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
	}

	cfg, err := createNewConfig(ConfigInput{ConfigPath: configPath})
	if err != nil {
		return nil, err
	}

	err = WriteOutConfig(configPath, cfg)
	return cfg, err
}

// UpdateConfig update existing configuration according to input configuration and return with the configuration
func UpdateConfig(input ConfigInput) (*Config, error) {
	if !configFileIsExists(input.ConfigPath) {
		return nil, status.Errorf(codes.NotFound, "config file doesn't exist")
	}

	return update(input)
}

// UpdateOrCreateConfig reads existing config or generates a new one
func UpdateOrCreateConfig(input ConfigInput) (*Config, error) {
	if !configFileIsExists(input.ConfigPath) {
		log.Infof("generating new config %s", input.ConfigPath)
		cfg, err := createNewConfig(input)
		if err != nil {
			return nil, err
		}
		err = WriteOutConfig(input.ConfigPath, cfg)
		return cfg, err
	}

	if isPreSharedKeyHidden(input.PreSharedKey) {
		input.PreSharedKey = nil
	}
	return update(input)
}

// CreateInMemoryConfig generate a new config but do not write out it to the store
func CreateInMemoryConfig(input ConfigInput) (*Config, error) {
	return createNewConfig(input)
}

// WriteOutConfig write put the prepared config to the given path
func WriteOutConfig(path string, config *Config) error {
	return util.WriteJson(path, config)
}

// createNewConfig creates a new config generating a new Wireguard key and saving to file
func createNewConfig(input ConfigInput) (*Config, error) {
	config := &Config{
		// defaults to false only for new (post 0.26) configurations
		ServerSSHAllowed: util.False(),
	}

	if _, err := config.apply(input); err != nil {
		return nil, err
	}

	return config, nil
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
		if err := util.WriteJson(input.ConfigPath, config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

func (config *Config) apply(input ConfigInput) (updated bool, err error) {
	if config.ManagementURL == nil {
		log.Infof("using default Management URL %s", DefaultManagementURL)
		config.ManagementURL, err = parseURL("Management URL", DefaultManagementURL)
		if err != nil {
			return false, err
		}
	}
	if input.ManagementURL != "" && input.ManagementURL != config.ManagementURL.String() {
		log.Infof("new Management URL provided, updated to %#v (old value %#v)",
			input.ManagementURL, config.ManagementURL.String())
		URL, err := parseURL("Management URL", input.ManagementURL)
		if err != nil {
			return false, err
		}
		config.ManagementURL = URL
		updated = true
	} else if config.ManagementURL == nil {
		log.Infof("using default Management URL %s", DefaultManagementURL)
		config.ManagementURL, err = parseURL("Management URL", DefaultManagementURL)
		if err != nil {
			return false, err
		}
	}

	if config.AdminURL == nil {
		log.Infof("using default Admin URL %s", DefaultManagementURL)
		config.AdminURL, err = parseURL("Admin URL", DefaultAdminURL)
		if err != nil {
			return false, err
		}
	}
	if input.AdminURL != "" && input.AdminURL != config.AdminURL.String() {
		log.Infof("new Admin Panel URL provided, updated to %#v (old value %#v)",
			input.AdminURL, config.AdminURL.String())
		newURL, err := parseURL("Admin Panel URL", input.AdminURL)
		if err != nil {
			return updated, err
		}
		config.AdminURL = newURL
		updated = true
	}

	if config.PrivateKey == "" {
		log.Infof("generated new Wireguard key")
		config.PrivateKey = generateKey()
		updated = true
	}

	if config.SSHKey == "" {
		log.Infof("generated new SSH key")
		pem, err := ssh.GeneratePrivateKey(ssh.ED25519)
		if err != nil {
			return false, err
		}
		config.SSHKey = string(pem)
		updated = true
	}

	if input.WireguardPort != nil && *input.WireguardPort != config.WgPort {
		log.Infof("updating Wireguard port %d (old value %d)",
			*input.WireguardPort, config.WgPort)
		config.WgPort = *input.WireguardPort
		updated = true
	} else if config.WgPort == 0 {
		config.WgPort = iface.DefaultWgPort
		log.Infof("using default Wireguard port %d", config.WgPort)
		updated = true
	}

	if input.InterfaceName != nil && *input.InterfaceName != config.WgIface {
		log.Infof("updating Wireguard interface %#v (old value %#v)",
			*input.InterfaceName, config.WgIface)
		config.WgIface = *input.InterfaceName
		updated = true
	} else if config.WgIface == "" {
		config.WgIface = iface.WgInterfaceDefault
		log.Infof("using default Wireguard interface %s", config.WgIface)
		updated = true
	}

	if input.NATExternalIPs != nil && !reflect.DeepEqual(config.NATExternalIPs, input.NATExternalIPs) {
		log.Infof("updating NAT External IP [ %s ] (old value: [ %s ])",
			strings.Join(input.NATExternalIPs, " "),
			strings.Join(config.NATExternalIPs, " "))
		config.NATExternalIPs = input.NATExternalIPs
		updated = true
	}

	if input.PreSharedKey != nil && *input.PreSharedKey != config.PreSharedKey {
		log.Infof("new pre-shared key provided, replacing old key")
		config.PreSharedKey = *input.PreSharedKey
		updated = true
	}

	if input.RosenpassEnabled != nil && *input.RosenpassEnabled != config.RosenpassEnabled {
		log.Infof("switching Rosenpass to %t", *input.RosenpassEnabled)
		config.RosenpassEnabled = *input.RosenpassEnabled
		updated = true
	}

	if input.RosenpassPermissive != nil && *input.RosenpassPermissive != config.RosenpassPermissive {
		log.Infof("switching Rosenpass permissive to %t", *input.RosenpassPermissive)
		config.RosenpassPermissive = *input.RosenpassPermissive
		updated = true
	}

	if input.NetworkMonitor != nil && *input.NetworkMonitor != config.NetworkMonitor {
		log.Infof("switching Network Monitor to %t", *input.NetworkMonitor)
		config.NetworkMonitor = *input.NetworkMonitor
		updated = true
	}

	if input.CustomDNSAddress != nil && string(input.CustomDNSAddress) != config.CustomDNSAddress {
		log.Infof("updating custom DNS address %#v (old value %#v)",
			string(input.CustomDNSAddress), config.CustomDNSAddress)
		config.CustomDNSAddress = string(input.CustomDNSAddress)
		updated = true
	}

	if len(config.IFaceBlackList) == 0 {
		log.Infof("filling in interface blacklist with defaults: [ %s ]",
			strings.Join(defaultInterfaceBlacklist, " "))
		config.IFaceBlackList = append(config.IFaceBlackList, defaultInterfaceBlacklist...)
		updated = true
	}

	if len(input.ExtraIFaceBlackList) > 0 {
		for _, iFace := range util.SliceDiff(input.ExtraIFaceBlackList, config.IFaceBlackList) {
			log.Infof("adding new entry to interface blacklist: %s", iFace)
			config.IFaceBlackList = append(config.IFaceBlackList, iFace)
			updated = true
		}
	}

	if input.DisableAutoConnect != nil && *input.DisableAutoConnect != config.DisableAutoConnect {
		if *input.DisableAutoConnect {
			log.Infof("turning off automatic connection on startup")
		} else {
			log.Infof("enabling automatic connection on startup")
		}
		config.DisableAutoConnect = *input.DisableAutoConnect
		updated = true
	}

	if input.ServerSSHAllowed != nil && *input.ServerSSHAllowed != *config.ServerSSHAllowed {
		if *input.ServerSSHAllowed {
			log.Infof("enabling SSH server")
		} else {
			log.Infof("disabling SSH server")
		}
		config.ServerSSHAllowed = input.ServerSSHAllowed
		updated = true
	} else if config.ServerSSHAllowed == nil {
		// enables SSH for configs from old versions to preserve backwards compatibility
		log.Infof("falling back to enabled SSH server for pre-existing configuration")
		config.ServerSSHAllowed = util.True()
		updated = true
	}

	return updated, nil
}

// parseURL parses and validates a service URL
func parseURL(serviceName, serviceURL string) (*url.URL, error) {
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
			parsedMgmtURL.Host += ":443"
		case "http":
			parsedMgmtURL.Host += ":80"
		default:
			log.Infof("unable to determine a default port for schema %s in URL %s", parsedMgmtURL.Scheme, serviceURL)
		}
	}

	return parsedMgmtURL, err
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

func configFileIsExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
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
