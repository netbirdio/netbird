package profilemanager

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"reflect"
	"runtime"
	"slices"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/dynamic"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/util"
)

func (config *Config) apply(input ConfigInput) (updated bool, err error) {
	if err = config.applyURLDefaults(); err != nil {
		return false, err
	}

	if u, err := config.applyManagementURL(input); err != nil {
		return false, err
	} else {
		updated = updated || u
	}

	if u, err := config.applyAdminURL(input); err != nil {
		return false, err
	} else {
		updated = updated || u
	}

	if u, err := config.applyCredentials(input); err != nil {
		return false, err
	} else {
		updated = updated || u
	}

	updated = config.applyInterfaceSettings(input) || updated
	updated = config.applyNetworkSettings(input) || updated
	updated = config.applyServerSettings(input) || updated
	updated = config.applySSHSettings(input) || updated
	updated = config.applyRouteSettings(input) || updated
	updated = config.applyDNSSettings(input) || updated
	updated = config.applyNotificationSettings(input) || updated
	updated = config.applyMTUSettings(input) || updated

	if u, err := config.applyClientCert(input); err != nil {
		return false, err
	} else {
		updated = updated || u
	}

	if input.LazyConnectionEnabled != nil && *input.LazyConnectionEnabled != config.LazyConnectionEnabled {
		log.Infof("switching lazy connection to %t", *input.LazyConnectionEnabled)
		config.LazyConnectionEnabled = *input.LazyConnectionEnabled
		updated = true
	}

	return updated, nil
}

// applyURLDefaults ensures ManagementURL and AdminURL are non-nil with defaults.
func (config *Config) applyURLDefaults() error {
	if config.ManagementURL == nil {
		log.Infof("using default Management URL %s", DefaultManagementURL)
		u, err := parseURL("Management URL", DefaultManagementURL)
		if err != nil {
			return err
		}
		config.ManagementURL = u
	}
	if config.AdminURL == nil {
		log.Infof("using default Admin URL %s", DefaultAdminURL)
		u, err := parseURL("Admin URL", DefaultAdminURL)
		if err != nil {
			return err
		}
		config.AdminURL = u
	}
	return nil
}

// applyManagementURL updates ManagementURL when input provides a new value.
func (config *Config) applyManagementURL(input ConfigInput) (bool, error) {
	if input.ManagementURL == "" || input.ManagementURL == config.ManagementURL.String() {
		return false, nil
	}
	log.Infof("new Management URL provided, updated to %#v (old value %#v)",
		input.ManagementURL, config.ManagementURL.String())
	u, err := parseURL("Management URL", input.ManagementURL)
	if err != nil {
		return false, err
	}
	config.ManagementURL = u
	return true, nil
}

// applyAdminURL updates AdminURL when input provides a new value.
func (config *Config) applyAdminURL(input ConfigInput) (bool, error) {
	if input.AdminURL == "" || input.AdminURL == config.AdminURL.String() {
		return false, nil
	}
	log.Infof("new Admin Panel URL provided, updated to %#v (old value %#v)",
		input.AdminURL, config.AdminURL.String())
	u, err := parseURL("Admin Panel URL", input.AdminURL)
	if err != nil {
		return false, err
	}
	config.AdminURL = u
	return true, nil
}

// applyCredentials generates missing private/SSH keys and updates the pre-shared key.
func (config *Config) applyCredentials(input ConfigInput) (bool, error) {
	updated := false

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

	if input.PreSharedKey != nil && *input.PreSharedKey != config.PreSharedKey {
		log.Infof("new pre-shared key provided, replacing old key")
		config.PreSharedKey = *input.PreSharedKey
		updated = true
	}

	return updated, nil
}

// applyInterfaceSettings handles WireGuard port, interface name, NAT IPs, and the extra blocklist.
func (config *Config) applyInterfaceSettings(input ConfigInput) bool {
	updated := false

	if input.WireguardPort != nil && *input.WireguardPort != config.WgPort {
		log.Infof("updating Wireguard port %d (old value %d)",
			*input.WireguardPort, config.WgPort)
		config.WgPort = *input.WireguardPort
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

	if len(config.IFaceBlackList) == 0 {
		log.Infof("filling in interface blacklist with defaults: [ %s ]",
			strings.Join(DefaultInterfaceBlacklist, " "))
		config.IFaceBlackList = append(config.IFaceBlackList, DefaultInterfaceBlacklist...)
		updated = true
	}

	if len(input.ExtraIFaceBlackList) > 0 {
		for _, iFace := range util.SliceDiff(input.ExtraIFaceBlackList, config.IFaceBlackList) {
			log.Infof("adding new entry to interface blacklist: %s", iFace)
			config.IFaceBlackList = append(config.IFaceBlackList, iFace)
			updated = true
		}
	}

	return updated
}

// applyNetworkSettings handles the network monitor and Rosenpass settings.
func (config *Config) applyNetworkSettings(input ConfigInput) bool {
	updated := false

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

	if input.NetworkMonitor != nil && input.NetworkMonitor != config.NetworkMonitor {
		log.Infof("switching Network Monitor to %t", *input.NetworkMonitor)
		config.NetworkMonitor = input.NetworkMonitor
		updated = true
	}

	if config.NetworkMonitor == nil {
		// enable network monitoring by default on windows and darwin clients
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			enabled := true
			config.NetworkMonitor = &enabled
			updated = true
		}
	}

	return updated
}

// applyServerSettings handles auto-connect and server-side SSH toggle.
func (config *Config) applyServerSettings(input ConfigInput) bool {
	updated := false

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
		if runtime.GOOS == "android" {
			// default to disabled SSH on Android for security
			log.Infof("setting SSH server to false by default on Android")
			config.ServerSSHAllowed = util.False()
		} else {
			// enables SSH for configs from old versions to preserve backwards compatibility
			log.Infof("falling back to enabled SSH server for pre-existing configuration")
			config.ServerSSHAllowed = util.True()
		}
		updated = true
	}

	return updated
}

// applySSHSettings handles granular SSH feature flags.
func (config *Config) applySSHSettings(input ConfigInput) bool {
	updated := false

	if input.EnableSSHRoot != nil && input.EnableSSHRoot != config.EnableSSHRoot {
		if *input.EnableSSHRoot {
			log.Infof("enabling SSH root login")
		} else {
			log.Infof("disabling SSH root login")
		}
		config.EnableSSHRoot = input.EnableSSHRoot
		updated = true
	}

	if input.EnableSSHSFTP != nil && input.EnableSSHSFTP != config.EnableSSHSFTP {
		if *input.EnableSSHSFTP {
			log.Infof("enabling SSH SFTP subsystem")
		} else {
			log.Infof("disabling SSH SFTP subsystem")
		}
		config.EnableSSHSFTP = input.EnableSSHSFTP
		updated = true
	}

	if input.EnableSSHLocalPortForwarding != nil && input.EnableSSHLocalPortForwarding != config.EnableSSHLocalPortForwarding {
		if *input.EnableSSHLocalPortForwarding {
			log.Infof("enabling SSH local port forwarding")
		} else {
			log.Infof("disabling SSH local port forwarding")
		}
		config.EnableSSHLocalPortForwarding = input.EnableSSHLocalPortForwarding
		updated = true
	}

	if input.EnableSSHRemotePortForwarding != nil && input.EnableSSHRemotePortForwarding != config.EnableSSHRemotePortForwarding {
		if *input.EnableSSHRemotePortForwarding {
			log.Infof("enabling SSH remote port forwarding")
		} else {
			log.Infof("disabling SSH remote port forwarding")
		}
		config.EnableSSHRemotePortForwarding = input.EnableSSHRemotePortForwarding
		updated = true
	}

	if input.DisableSSHAuth != nil && input.DisableSSHAuth != config.DisableSSHAuth {
		if *input.DisableSSHAuth {
			log.Infof("disabling SSH authentication")
		} else {
			log.Infof("enabling SSH authentication")
		}
		config.DisableSSHAuth = input.DisableSSHAuth
		updated = true
	}

	if input.SSHJWTCacheTTL != nil && input.SSHJWTCacheTTL != config.SSHJWTCacheTTL {
		log.Infof("updating SSH JWT cache TTL to %d seconds", *input.SSHJWTCacheTTL)
		config.SSHJWTCacheTTL = input.SSHJWTCacheTTL
		updated = true
	}

	return updated
}

// applyRouteSettings handles client/server/default-route, DNS, firewall, LAN, inbound, and IPv6 toggles.
func (config *Config) applyRouteSettings(input ConfigInput) bool {
	updated := false

	if input.DNSRouteInterval != nil && *input.DNSRouteInterval != config.DNSRouteInterval {
		log.Infof("updating DNS route interval to %s (old value %s)",
			input.DNSRouteInterval.String(), config.DNSRouteInterval.String())
		config.DNSRouteInterval = *input.DNSRouteInterval
		updated = true
	} else if config.DNSRouteInterval == 0 {
		config.DNSRouteInterval = dynamic.DefaultInterval
		log.Infof("using default DNS route interval %s", config.DNSRouteInterval)
		updated = true
	}

	if input.DisableClientRoutes != nil && *input.DisableClientRoutes != config.DisableClientRoutes {
		if *input.DisableClientRoutes {
			log.Infof("disabling client routes")
		} else {
			log.Infof("enabling client routes")
		}
		config.DisableClientRoutes = *input.DisableClientRoutes
		updated = true
	}

	if input.DisableServerRoutes != nil && *input.DisableServerRoutes != config.DisableServerRoutes {
		if *input.DisableServerRoutes {
			log.Infof("disabling server routes")
		} else {
			log.Infof("enabling server routes")
		}
		config.DisableServerRoutes = *input.DisableServerRoutes
		updated = true
	}

	if input.DisableDefaultRoute != nil && *input.DisableDefaultRoute != config.DisableDefaultRoute {
		if *input.DisableDefaultRoute {
			log.Infof("disabling default route")
		} else {
			log.Infof("enabling default route")
		}
		config.DisableDefaultRoute = *input.DisableDefaultRoute
		updated = true
	}

	if input.DisableDNS != nil && *input.DisableDNS != config.DisableDNS {
		if *input.DisableDNS {
			log.Infof("disabling DNS configuration")
		} else {
			log.Infof("enabling DNS configuration")
		}
		config.DisableDNS = *input.DisableDNS
		updated = true
	}

	if input.DisableFirewall != nil && *input.DisableFirewall != config.DisableFirewall {
		if *input.DisableFirewall {
			log.Infof("disabling firewall configuration")
		} else {
			log.Infof("enabling firewall configuration")
		}
		config.DisableFirewall = *input.DisableFirewall
		updated = true
	}

	if input.BlockLANAccess != nil && *input.BlockLANAccess != config.BlockLANAccess {
		if *input.BlockLANAccess {
			log.Infof("blocking LAN access")
		} else {
			log.Infof("allowing LAN access")
		}
		config.BlockLANAccess = *input.BlockLANAccess
		updated = true
	}

	if input.BlockInbound != nil && *input.BlockInbound != config.BlockInbound {
		if *input.BlockInbound {
			log.Infof("blocking inbound connections")
		} else {
			log.Infof("allowing inbound connections")
		}
		config.BlockInbound = *input.BlockInbound
		updated = true
	}

	if input.DisableIPv6 != nil && *input.DisableIPv6 != config.DisableIPv6 {
		log.Infof("setting IPv6 overlay disabled=%v", *input.DisableIPv6)
		config.DisableIPv6 = *input.DisableIPv6
		updated = true
	}

	return updated
}

// applyDNSSettings handles custom DNS address and DNS labels.
func (config *Config) applyDNSSettings(input ConfigInput) bool {
	updated := false

	if input.CustomDNSAddress != nil && string(input.CustomDNSAddress) != config.CustomDNSAddress {
		log.Infof("updating custom DNS address %#v (old value %#v)",
			string(input.CustomDNSAddress), config.CustomDNSAddress)
		config.CustomDNSAddress = string(input.CustomDNSAddress)
		updated = true
	}

	if input.DNSLabels != nil && !slices.Equal(config.DNSLabels, input.DNSLabels) {
		log.Infof("updating DNS labels [ %s ] (old value: [ %s ])",
			input.DNSLabels.SafeString(),
			config.DNSLabels.SafeString())
		config.DNSLabels = input.DNSLabels
		updated = true
	}

	return updated
}

// applyNotificationSettings handles the DisableNotifications flag and its default.
func (config *Config) applyNotificationSettings(input ConfigInput) bool {
	updated := false

	if input.DisableNotifications != nil && input.DisableNotifications != config.DisableNotifications {
		if *input.DisableNotifications {
			log.Infof("disabling notifications")
		} else {
			log.Infof("enabling notifications")
		}
		config.DisableNotifications = input.DisableNotifications
		updated = true
	}

	if config.DisableNotifications == nil {
		disabled := true
		config.DisableNotifications = &disabled
		log.Infof("setting notifications to disabled by default")
		updated = true
	}

	return updated
}

// applyMTUSettings updates MTU or sets the default when it is zero.
func (config *Config) applyMTUSettings(input ConfigInput) bool {
	if input.MTU != nil && *input.MTU != config.MTU {
		log.Infof("updating MTU to %d (old value %d)", *input.MTU, config.MTU)
		config.MTU = *input.MTU
		return true
	}
	if config.MTU == 0 {
		config.MTU = iface.DefaultMTU
		log.Infof("using default MTU %d", config.MTU)
		return true
	}
	return false
}

// applyClientCert loads the mTLS key pair when paths are provided or already set.
func (config *Config) applyClientCert(input ConfigInput) (bool, error) {
	updated := false

	if input.ClientCertKeyPath != "" {
		config.ClientCertKeyPath = input.ClientCertKeyPath
		updated = true
	}

	if input.ClientCertPath != "" {
		config.ClientCertPath = input.ClientCertPath
		updated = true
	}

	if config.ClientCertPath != "" && config.ClientCertKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientCertKeyPath)
		if err != nil {
			log.Error("Failed to load mTLS cert/key pair: ", err)
		} else {
			config.ClientCertKeyPair = &cert
			log.Info("Loaded client mTLS cert/key pair")
		}
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
