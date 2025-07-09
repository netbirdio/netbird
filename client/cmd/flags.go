package cmd

import (
	"fmt"
	"time"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/spf13/cobra"
)

// SharedFlags contains all configuration flags that are common between up and set commands
type SharedFlags struct {
	// Network configuration
	InterfaceName       string
	WireguardPort       uint16
	NATExternalIPs      []string
	CustomDNSAddress    string
	ExtraIFaceBlackList []string
	DNSLabels           []string
	DNSRouteInterval    time.Duration

	// Feature flags
	RosenpassEnabled    bool
	RosenpassPermissive bool
	ServerSSHAllowed    bool
	AutoConnectDisabled bool
	NetworkMonitor      bool
	LazyConnEnabled     bool

	// System flags
	DisableClientRoutes bool
	DisableServerRoutes bool
	DisableDNS          bool
	DisableFirewall     bool
	BlockLANAccess      bool
	BlockInbound        bool

	// Login-specific (only for up command)
	NoBrowser bool
}

// AddSharedFlags adds all shared configuration flags to the given command
func AddSharedFlags(cmd *cobra.Command, flags *SharedFlags) {
	// Network configuration flags
	cmd.PersistentFlags().StringVar(&flags.InterfaceName, interfaceNameFlag, iface.WgInterfaceDefault,
		"Wireguard interface name")
	cmd.PersistentFlags().Uint16Var(&flags.WireguardPort, wireguardPortFlag, iface.DefaultWgPort,
		"Wireguard interface listening port")
	cmd.PersistentFlags().StringSliceVar(&flags.NATExternalIPs, externalIPMapFlag, nil,
		`Sets external IPs maps between local addresses and interfaces. `+
			`You can specify a comma-separated list with a single IP and IP/IP or IP/Interface Name. `+
			`An empty string "" clears the previous configuration. `+
			`E.g. --external-ip-map 12.34.56.78/10.0.0.1 or --external-ip-map 12.34.56.200,12.34.56.78/10.0.0.1,12.34.56.80/eth1 `+
			`or --external-ip-map ""`)
	cmd.PersistentFlags().StringVar(&flags.CustomDNSAddress, dnsResolverAddress, "",
		`Sets a custom address for NetBird's local DNS resolver. `+
			`If set, the agent won't attempt to discover the best ip and port to listen on. `+
			`An empty string "" clears the previous configuration. `+
			`E.g. --dns-resolver-address 127.0.0.1:5053 or --dns-resolver-address ""`)
	cmd.PersistentFlags().StringSliceVar(&flags.ExtraIFaceBlackList, extraIFaceBlackListFlag, nil,
		"Extra list of default interfaces to ignore for listening")
	cmd.PersistentFlags().StringSliceVar(&flags.DNSLabels, dnsLabelsFlag, nil,
		`Sets DNS labels. `+
			`You can specify a comma-separated list of up to 32 labels. `+
			`An empty string "" clears the previous configuration. `+
			`E.g. --extra-dns-labels vpc1 or --extra-dns-labels vpc1,mgmt1 `+
			`or --extra-dns-labels ""`)
	cmd.PersistentFlags().DurationVar(&flags.DNSRouteInterval, dnsRouteIntervalFlag, time.Minute,
		"DNS route update interval")

	// Feature flags
	cmd.PersistentFlags().BoolVar(&flags.RosenpassEnabled, enableRosenpassFlag, false,
		"[Experimental] Enable Rosenpass feature. If enabled, the connection will be post-quantum secured via Rosenpass.")
	cmd.PersistentFlags().BoolVar(&flags.RosenpassPermissive, rosenpassPermissiveFlag, false,
		"[Experimental] Enable Rosenpass in permissive mode to allow this peer to accept WireGuard connections without requiring Rosenpass functionality from peers that do not have Rosenpass enabled.")
	cmd.PersistentFlags().BoolVar(&flags.ServerSSHAllowed, serverSSHAllowedFlag, false,
		"Allow SSH server on peer. If enabled, the SSH server will be permitted")
	cmd.PersistentFlags().BoolVar(&flags.AutoConnectDisabled, disableAutoConnectFlag, false,
		"Disables auto-connect feature. If enabled, then the client won't connect automatically when the service starts.")
	cmd.PersistentFlags().BoolVarP(&flags.NetworkMonitor, networkMonitorFlag, "N", networkMonitor,
		`Manage network monitoring. Defaults to true on Windows and macOS, false on Linux and FreeBSD. `+
			`E.g. --network-monitor=false to disable or --network-monitor=true to enable.`)
	cmd.PersistentFlags().BoolVar(&flags.LazyConnEnabled, enableLazyConnectionFlag, false,
		"[Experimental] Enable the lazy connection feature. If enabled, the client will establish connections on-demand.")

	// System flags (from system.go)
	cmd.PersistentFlags().BoolVar(&flags.DisableClientRoutes, disableClientRoutesFlag, false,
		"Disable client routes. If enabled, the client won't process client routes received from the management service.")
	cmd.PersistentFlags().BoolVar(&flags.DisableServerRoutes, disableServerRoutesFlag, false,
		"Disable server routes. If enabled, the client won't act as a router for server routes received from the management service.")
	cmd.PersistentFlags().BoolVar(&flags.DisableDNS, disableDNSFlag, false,
		"Disable DNS. If enabled, the client won't configure DNS settings.")
	cmd.PersistentFlags().BoolVar(&flags.DisableFirewall, disableFirewallFlag, false,
		"Disable firewall configuration. If enabled, the client won't modify firewall rules.")
	cmd.PersistentFlags().BoolVar(&flags.BlockLANAccess, blockLANAccessFlag, false,
		"Block access to local networks (LAN) when using this peer as a router or exit node")
	cmd.PersistentFlags().BoolVar(&flags.BlockInbound, blockInboundFlag, false,
		"Block inbound connections. If enabled, the client will not allow any inbound connections to the local machine nor routed networks.\n"+
			"This overrides any policies received from the management service.")
}

// AddUpOnlyFlags adds flags that are specific to the up command
func AddUpOnlyFlags(cmd *cobra.Command, flags *SharedFlags) {
	cmd.PersistentFlags().BoolVar(&flags.NoBrowser, noBrowserFlag, false, noBrowserDesc)
}

// BuildConfigInput creates an internal.ConfigInput from SharedFlags with Changed() checks
func BuildConfigInput(cmd *cobra.Command, flags *SharedFlags, customDNSAddressConverted []byte) (*internal.ConfigInput, error) {
	ic := internal.ConfigInput{
		ManagementURL:    managementURL,
		AdminURL:         adminURL,
		ConfigPath:       configPath,
		CustomDNSAddress: customDNSAddressConverted,
	}

	// Handle PreSharedKey from root command
	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		ic.PreSharedKey = &preSharedKey
	}

	if cmd.Flag(enableRosenpassFlag).Changed {
		ic.RosenpassEnabled = &flags.RosenpassEnabled
	}

	if cmd.Flag(rosenpassPermissiveFlag).Changed {
		ic.RosenpassPermissive = &flags.RosenpassPermissive
	}

	if cmd.Flag(serverSSHAllowedFlag).Changed {
		ic.ServerSSHAllowed = &flags.ServerSSHAllowed
	}

	if cmd.Flag(interfaceNameFlag).Changed {
		if err := parseInterfaceName(flags.InterfaceName); err != nil {
			return nil, err
		}
		ic.InterfaceName = &flags.InterfaceName
	}

	if cmd.Flag(wireguardPortFlag).Changed {
		p := int(flags.WireguardPort)
		ic.WireguardPort = &p
	}

	if cmd.Flag(networkMonitorFlag).Changed {
		ic.NetworkMonitor = &flags.NetworkMonitor
	}

	if cmd.Flag(disableAutoConnectFlag).Changed {
		ic.DisableAutoConnect = &flags.AutoConnectDisabled

		if flags.AutoConnectDisabled {
			cmd.Println("Autoconnect has been disabled. The client won't connect automatically when the service starts.")
		} else {
			cmd.Println("Autoconnect has been enabled. The client will connect automatically when the service starts.")
		}
	}

	if cmd.Flag(dnsRouteIntervalFlag).Changed {
		ic.DNSRouteInterval = &flags.DNSRouteInterval
	}

	if cmd.Flag(disableClientRoutesFlag).Changed {
		ic.DisableClientRoutes = &flags.DisableClientRoutes
	}

	if cmd.Flag(disableServerRoutesFlag).Changed {
		ic.DisableServerRoutes = &flags.DisableServerRoutes
	}

	if cmd.Flag(disableDNSFlag).Changed {
		ic.DisableDNS = &flags.DisableDNS
	}

	if cmd.Flag(disableFirewallFlag).Changed {
		ic.DisableFirewall = &flags.DisableFirewall
	}

	if cmd.Flag(blockLANAccessFlag).Changed {
		ic.BlockLANAccess = &flags.BlockLANAccess
	}

	if cmd.Flag(blockInboundFlag).Changed {
		ic.BlockInbound = &flags.BlockInbound
	}

	if cmd.Flag(enableLazyConnectionFlag).Changed {
		ic.LazyConnectionEnabled = &flags.LazyConnEnabled
	}

	if cmd.Flag(externalIPMapFlag).Changed {
		ic.NATExternalIPs = flags.NATExternalIPs
	}

	if cmd.Flag(extraIFaceBlackListFlag).Changed {
		ic.ExtraIFaceBlackList = flags.ExtraIFaceBlackList
	}

	if cmd.Flag(dnsLabelsFlag).Changed {
		var err error
		ic.DNSLabels, err = domain.FromStringList(flags.DNSLabels)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS labels: %v", err)
		}
	}

	return &ic, nil
}
