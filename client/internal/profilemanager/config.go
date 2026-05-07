package profilemanager

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/util"
)

const (
	// managementLegacyPortString is the port that was used before by the Management gRPC server.
	// It is used for backward compatibility now.
	managementLegacyPortString = "33073"
	// DefaultManagementURL points to the NetBird's cloud management endpoint
	DefaultManagementURL = "https://api.netbird.io:443"
	// oldDefaultManagementURL points to the NetBird's old cloud management endpoint
	oldDefaultManagementURL = "https://api.wiretrustee.com:443"
	// DefaultAdminURL points to NetBird's cloud management console
	DefaultAdminURL = "https://app.netbird.io:443"
)

// mgmProber is the subset of management client needed for URL migration probes.
type mgmProber interface {
	HealthCheck() error
	Close() error
}

// newMgmProber creates a management client for probing URL reachability.
// Overridden in tests to avoid real network calls.
var newMgmProber = func(ctx context.Context, addr string, key wgtypes.Key, tlsEnabled bool) (mgmProber, error) {
	return mgm.NewClient(ctx, addr, key, tlsEnabled)
}

var DefaultInterfaceBlacklist = []string{
	iface.WgInterfaceDefault, "wt", "utun", "tun0", "zt", "ZeroTier", "wg", "ts",
	"Tailscale", "tailscale", "docker", "veth", "br-", "lo",
}

// ConfigInput carries configuration changes to the client
type ConfigInput struct {
	ManagementURL                 string
	AdminURL                      string
	ConfigPath                    string
	StateFilePath                 string
	PreSharedKey                  *string
	ServerSSHAllowed              *bool
	EnableSSHRoot                 *bool
	EnableSSHSFTP                 *bool
	EnableSSHLocalPortForwarding  *bool
	EnableSSHRemotePortForwarding *bool
	DisableSSHAuth                *bool
	SSHJWTCacheTTL                *int
	NATExternalIPs                []string
	CustomDNSAddress              []byte
	RosenpassEnabled              *bool
	RosenpassPermissive           *bool
	InterfaceName                 *string
	WireguardPort                 *int
	NetworkMonitor                *bool
	DisableAutoConnect            *bool
	ExtraIFaceBlackList           []string
	DNSRouteInterval              *time.Duration
	ClientCertPath                string
	ClientCertKeyPath             string

	DisableClientRoutes *bool
	DisableServerRoutes *bool
	DisableDefaultRoute *bool
	DisableDNS          *bool
	DisableFirewall     *bool
	BlockLANAccess      *bool
	BlockInbound        *bool
	DisableIPv6         *bool

	DisableNotifications *bool

	DNSLabels domain.List

	LazyConnectionEnabled *bool

	MTU *uint16
}

// Config Configuration type
type Config struct {
	// Wireguard private key of local peer
	PrivateKey                    string
	PreSharedKey                  string
	ManagementURL                 *url.URL
	AdminURL                      *url.URL
	WgIface                       string
	WgPort                        int
	NetworkMonitor                *bool
	IFaceBlackList                []string
	DisableIPv6Discovery          bool
	RosenpassEnabled              bool
	RosenpassPermissive           bool
	ServerSSHAllowed              *bool
	EnableSSHRoot                 *bool
	EnableSSHSFTP                 *bool
	EnableSSHLocalPortForwarding  *bool
	EnableSSHRemotePortForwarding *bool
	DisableSSHAuth                *bool
	SSHJWTCacheTTL                *int

	DisableClientRoutes bool
	DisableServerRoutes bool
	DisableDefaultRoute bool
	DisableDNS          bool
	DisableFirewall     bool
	BlockLANAccess      bool
	BlockInbound        bool
	DisableIPv6         bool

	DisableNotifications *bool

	DNSLabels domain.List

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

	// DNSRouteInterval is the interval in which the DNS routes are updated
	DNSRouteInterval time.Duration
	// Path to a certificate used for mTLS authentication
	ClientCertPath string

	// Path to corresponding private key of ClientCertPath
	ClientCertKeyPath string

	ClientCertKeyPair *tls.Certificate `json:"-"`

	LazyConnectionEnabled bool

	MTU uint16
}

var ConfigDirOverride string

func getConfigDir() (string, error) {
	if ConfigDirOverride != "" {
		return ConfigDirOverride, nil
	}

	base, err := baseConfigDir()
	if err != nil {
		return "", err
	}

	configDir := filepath.Join(base, "netbird")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return "", err
	}
	return configDir, nil
}

func baseConfigDir() (string, error) {
	if runtime.GOOS == "darwin" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			return filepath.Join(u.HomeDir, "Library", "Application Support"), nil
		}
	}
	return os.UserConfigDir()
}

func getConfigDirForUser(username string) (string, error) {
	if ConfigDirOverride != "" {
		return ConfigDirOverride, nil
	}

	username = sanitizeProfileName(username)

	configDir := filepath.Join(DefaultConfigPathDir, username)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return "", err
		}
	}

	return configDir, nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// createNewConfig creates a new config generating a new Wireguard key and saving to file
func createNewConfig(input ConfigInput) (*Config, error) {
	config := &Config{
		// defaults to false only for new (post 0.26) configurations
		ServerSSHAllowed: util.False(),
		WgPort:           iface.DefaultWgPort,
	}

	if _, err := config.apply(input); err != nil {
		return nil, err
	}

	return config, nil
}

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

	newURL, err := parseURL("Management URL", fmt.Sprintf("%s://%s", config.ManagementURL.Scheme, net.JoinHostPort(defaultManagementURL.Hostname(), "443")))
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

	client, err := newMgmProber(ctx, newURL.Host, key, mgmTlsEnabled)
	if err != nil {
		log.Infof("couldn't switch to the new Management %s", newURL.String())
		return config, err
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Warnf("failed to close the Management service client %v", err)
		}
	}()

	// gRPC check
	if err = client.HealthCheck(); err != nil {
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

// ReadConfig read config file and return with Config. If it is not exists create a new with default values
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
