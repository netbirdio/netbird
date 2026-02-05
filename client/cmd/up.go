package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/user"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/util"
)

const (
	invalidInputType int = iota
	ipInputType
	interfaceInputType
)

const (
	dnsLabelsFlag            = "extra-dns-labels"
	extraIFaceBlackListFlag  = "extra-iface-blacklist"
	externalIPMapFlag        = "external-ip-map"
	dnsResolverAddress       = "dns-resolver-address"
	enableRosenpassFlag      = "enable-rosenpass"
	rosenpassPermissiveFlag  = "rosenpass-permissive"
	disableAutoConnectFlag   = "disable-auto-connect"
	enableLazyConnectionFlag = "enable-lazy-connection"

	noBrowserFlag = "no-browser"
	noBrowserDesc = "do not open the browser for SSO login"

	profileNameFlag = "profile"
	profileNameDesc = "profile name to use for the login. If not specified, the last used profile will be used."
)

var (
	foregroundMode      bool
	dnsLabels           []string
	dnsLabelsValidated  domain.List
	extraIFaceBlackList []string
	natExternalIPs      []string
	customDNSAddress    string
	rosenpassEnabled    bool
	rosenpassPermissive bool
	autoConnectDisabled bool
	lazyConnEnabled     bool
	noBrowser           bool
	profileName         string
	configPath          string

	upCmd = &cobra.Command{
		Use:   "up",
		Short: "Connect to the NetBird network",
		Long:  "Connect to the NetBird network using the provided setup key or SSO auth. This command will bring up the WireGuard interface, connect to the management server, and establish peer-to-peer connections with other peers in the network if required.",
		RunE:  upFunc,
	}
)

func init() {
	upCmd.PersistentFlags().BoolVarP(&foregroundMode, "foreground-mode", "F", false, "start service in foreground")
	upCmd.PersistentFlags().StringVar(&interfaceName, interfaceNameFlag, iface.WgInterfaceDefault, "WireGuard interface name")
	upCmd.PersistentFlags().Uint16Var(&wireguardPort, wireguardPortFlag, iface.DefaultWgPort, "WireGuard interface listening port")
	upCmd.PersistentFlags().Uint16Var(&mtu, mtuFlag, iface.DefaultMTU, "Set MTU (Maximum Transmission Unit) for the WireGuard interface")
	upCmd.PersistentFlags().BoolVarP(&networkMonitor, networkMonitorFlag, "N", networkMonitor,
		`Manage network monitoring. Defaults to true on Windows and macOS, false on Linux and FreeBSD. `+
			`E.g. --network-monitor=false to disable or --network-monitor=true to enable.`,
	)
	upCmd.PersistentFlags().StringSliceVar(&extraIFaceBlackList, extraIFaceBlackListFlag, nil, "Extra list of default interfaces to ignore for listening")
	upCmd.PersistentFlags().DurationVar(&dnsRouteInterval, dnsRouteIntervalFlag, time.Minute, "DNS route update interval")

	upCmd.PersistentFlags().StringSliceVar(&dnsLabels, dnsLabelsFlag, nil,
		`Sets DNS labels`+
			`You can specify a comma-separated list of up to 32 labels. `+
			`An empty string "" clears the previous configuration. `+
			`E.g. --extra-dns-labels vpc1 or --extra-dns-labels vpc1,mgmt1 `+
			`or --extra-dns-labels ""`,
	)

	upCmd.PersistentFlags().BoolVar(&noBrowser, noBrowserFlag, false, noBrowserDesc)
	upCmd.PersistentFlags().StringVar(&profileName, profileNameFlag, "", profileNameDesc)
	upCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "(DEPRECATED) NetBird config file location. ")

	upCmd.PersistentFlags().StringSliceVar(&natExternalIPs, externalIPMapFlag, nil,
		`Sets external IPs maps between local addresses and interfaces.`+
			`You can specify a comma-separated list with a single IP and IP/IP or IP/Interface Name. `+
			`An empty string "" clears the previous configuration. `+
			`E.g. --external-ip-map 12.34.56.78/10.0.0.1 or --external-ip-map 12.34.56.200,12.34.56.78/10.0.0.1,12.34.56.80/eth1 `+
			`or --external-ip-map ""`,
	)
	upCmd.PersistentFlags().StringVar(&customDNSAddress, dnsResolverAddress, "",
		`Sets a custom address for NetBird's local DNS resolver. `+
			`If set, the agent won't attempt to discover the best ip and port to listen on. `+
			`An empty string "" clears the previous configuration. `+
			`E.g. --dns-resolver-address 127.0.0.1:5053 or --dns-resolver-address ""`,
	)
	upCmd.PersistentFlags().BoolVar(&rosenpassEnabled, enableRosenpassFlag, false, "[Experimental] Enable Rosenpass feature. If enabled, the connection will be post-quantum secured via Rosenpass.")
	upCmd.PersistentFlags().BoolVar(&rosenpassPermissive, rosenpassPermissiveFlag, false, "[Experimental] Enable Rosenpass in permissive mode to allow this peer to accept WireGuard connections without requiring Rosenpass functionality from peers that do not have Rosenpass enabled.")
	upCmd.PersistentFlags().BoolVar(&autoConnectDisabled, disableAutoConnectFlag, false, "Disables auto-connect feature. If enabled, then the client won't connect automatically when the service starts.")
	upCmd.PersistentFlags().BoolVar(&lazyConnEnabled, enableLazyConnectionFlag, false, "[Experimental] Enable the lazy connection feature. If enabled, the client will establish connections on-demand. Note: this setting may be overridden by management configuration.")

}

func upFunc(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)

	cmd.SetOut(cmd.OutOrStdout())

	err := util.InitLog(logLevel, util.LogConsole)
	if err != nil {
		return fmt.Errorf("failed initializing log %v", err)
	}

	err = validateNATExternalIPs(natExternalIPs)
	if err != nil {
		return err
	}

	dnsLabelsValidated, err = validateDnsLabels(dnsLabels)
	if err != nil {
		return err
	}

	ctx := internal.CtxInitState(cmd.Context())

	if hostName != "" {
		// nolint
		ctx = context.WithValue(ctx, system.DeviceNameCtxKey, hostName)
	}

	pm := profilemanager.NewProfileManager()

	username, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %v", err)
	}

	// getActiveProfile will also switch the profile if needed
	activeProf, err := getActiveProfile(cmd.Context(), pm, profileName, username.Username)
	if err != nil {
		return fmt.Errorf("get active profile: %v", err)
	}

	// if non-empty profileName, this means that we switched profile
	profileSwitched := profileName != ""

	if foregroundMode {
		return runInForegroundMode(ctx, cmd, activeProf)
	}
	return runInDaemonMode(ctx, cmd, pm, activeProf, profileSwitched)
}

func runInForegroundMode(ctx context.Context, cmd *cobra.Command, activeProf *profilemanager.Profile) error {
	ic, err := setupConfigInputFromUpCmd(cmd)
	if err != nil {
		return fmt.Errorf("setup config: %v", err)
	}

	config, err := doForegroundLogin(ctx, cmd, activeProf, ic)
	if err != nil {
		return err
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	SetupCloseHandler(ctx, cancel)

	r := peer.NewRecorder(config.ManagementURL.String())
	r.GetFullStatus()

	connectClient := internal.NewConnectClient(ctx, config, r, false)
	SetupDebugHandler(ctx, config, r, connectClient, "")

	return connectClient.Run(nil, util.FindFirstLogPath(logFiles))
}

func runInDaemonMode(ctx context.Context, cmd *cobra.Command, pm *profilemanager.ProfileManager, activeProf *profilemanager.Profile, profileSwitched bool) error {
	// setup grpc connection
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()
	client := proto.NewDaemonServiceClient(conn)

	// setup daemon
	setConfigReq, err := setupSetConfigFromUpCmd(cmd)
	if err != nil {
		return err
	}

	if err := doDaemonSetup(ctx, cmd, client, profileSwitched, setConfigReq); err != nil {
		return fmt.Errorf("daemon setup failed: %v", err)
	}

	// login
	loginReq, err := setupLoginRequestFromUpCmd(cmd)
	if err != nil {
		return err
	}

	if err := doDaemonLogin(ctx, cmd, client, activeProf, pm, loginReq); err != nil {
		return fmt.Errorf("daemon login failed: %v", err)
	}

	if _, err := client.Up(ctx, &proto.UpRequest{
		ProfileName: &activeProf.Name,
		Username:    &username,
	}); err != nil {
		return fmt.Errorf("call service up method: %v", err)
	}

	cmd.Println("Connected")
	return nil
}

func setupSetConfigFromUpCmd(cmd *cobra.Command) (*proto.SetConfigRequest, error) {
	req := proto.SetConfigRequest{
		NatExternalIPs:      natExternalIPs,
		ExtraIFaceBlacklist: extraIFaceBlackList,
		DnsLabels:           dnsLabelsValidated.ToPunycodeList(),
		CleanDNSLabels:      dnsLabels != nil && len(dnsLabels) == 0,
		CleanNATExternalIPs: natExternalIPs != nil && len(natExternalIPs) == 0,
	}

	if cmd.Flag(dnsResolverAddress).Changed {
		var err error
		req.CustomDNSAddress, err = parseDNSAddress(customDNSAddress)
		if err != nil {
			return nil, err
		}
	}

	if cmd.Flag(enableRosenpassFlag).Changed {
		req.RosenpassEnabled = &rosenpassEnabled
	}
	if cmd.Flag(rosenpassPermissiveFlag).Changed {
		req.RosenpassPermissive = &rosenpassPermissive
	}
	if cmd.Flag(serverSSHAllowedFlag).Changed {
		req.ServerSSHAllowed = &serverSSHAllowed
	}
	if cmd.Flag(enableSSHRootFlag).Changed {
		req.EnableSSHRoot = &enableSSHRoot
	}
	if cmd.Flag(enableSSHSFTPFlag).Changed {
		req.EnableSSHSFTP = &enableSSHSFTP
	}
	if cmd.Flag(enableSSHLocalPortForwardFlag).Changed {
		req.EnableSSHLocalPortForwarding = &enableSSHLocalPortForward
	}
	if cmd.Flag(enableSSHRemotePortForwardFlag).Changed {
		req.EnableSSHRemotePortForwarding = &enableSSHRemotePortForward
	}
	if cmd.Flag(disableSSHAuthFlag).Changed {
		req.DisableSSHAuth = &disableSSHAuth
	}
	if cmd.Flag(sshJWTCacheTTLFlag).Changed {
		sshJWTCacheTTL32 := int32(sshJWTCacheTTL)
		req.SshJWTCacheTTL = &sshJWTCacheTTL32
	}
	if cmd.Flag(interfaceNameFlag).Changed {
		if err := parseInterfaceName(interfaceName); err != nil {
			log.Errorf("parse interface name: %v", err)
			return nil, err
		}
		req.InterfaceName = &interfaceName
	}
	if cmd.Flag(wireguardPortFlag).Changed {
		p := int64(wireguardPort)
		req.WireguardPort = &p
	}

	if cmd.Flag(mtuFlag).Changed {
		if err := iface.ValidateMTU(mtu); err != nil {
			return nil, err
		}
		m := int64(mtu)
		req.Mtu = &m
	}

	if cmd.Flag(networkMonitorFlag).Changed {
		req.NetworkMonitor = &networkMonitor
	}

	if cmd.Flag(disableAutoConnectFlag).Changed {
		req.DisableAutoConnect = &autoConnectDisabled
	}

	if cmd.Flag(dnsRouteIntervalFlag).Changed {
		req.DnsRouteInterval = durationpb.New(dnsRouteInterval)
	}

	if cmd.Flag(disableClientRoutesFlag).Changed {
		req.DisableClientRoutes = &disableClientRoutes
	}

	if cmd.Flag(disableServerRoutesFlag).Changed {
		req.DisableServerRoutes = &disableServerRoutes
	}

	if cmd.Flag(disableDNSFlag).Changed {
		req.DisableDns = &disableDNS
	}

	if cmd.Flag(disableFirewallFlag).Changed {
		req.DisableFirewall = &disableFirewall
	}

	if cmd.Flag(blockLANAccessFlag).Changed {
		req.BlockLanAccess = &blockLANAccess
	}

	if cmd.Flag(blockInboundFlag).Changed {
		req.BlockInbound = &blockInbound
	}

	if cmd.Flag(enableLazyConnectionFlag).Changed {
		req.LazyConnectionEnabled = &lazyConnEnabled
	}

	return &req, nil
}

func setupConfigInputFromUpCmd(cmd *cobra.Command) (*profilemanager.ConfigInput, error) {
	ic := profilemanager.ConfigInput{
		NATExternalIPs:      natExternalIPs,
		ExtraIFaceBlackList: extraIFaceBlackList,
		DNSLabels:           dnsLabelsValidated,
	}

	if cmd.Flag(dnsResolverAddress).Changed {
		var err error
		ic.CustomDNSAddress, err = parseDNSAddress(customDNSAddress)
		if err != nil {
			return nil, err
		}
	}

	if cmd.Flag(enableRosenpassFlag).Changed {
		ic.RosenpassEnabled = &rosenpassEnabled
	}

	if cmd.Flag(rosenpassPermissiveFlag).Changed {
		ic.RosenpassPermissive = &rosenpassPermissive
	}

	if cmd.Flag(serverSSHAllowedFlag).Changed {
		ic.ServerSSHAllowed = &serverSSHAllowed
	}

	if cmd.Flag(enableSSHRootFlag).Changed {
		ic.EnableSSHRoot = &enableSSHRoot
	}

	if cmd.Flag(enableSSHSFTPFlag).Changed {
		ic.EnableSSHSFTP = &enableSSHSFTP
	}

	if cmd.Flag(enableSSHLocalPortForwardFlag).Changed {
		ic.EnableSSHLocalPortForwarding = &enableSSHLocalPortForward
	}

	if cmd.Flag(enableSSHRemotePortForwardFlag).Changed {
		ic.EnableSSHRemotePortForwarding = &enableSSHRemotePortForward
	}

	if cmd.Flag(disableSSHAuthFlag).Changed {
		ic.DisableSSHAuth = &disableSSHAuth
	}

	if cmd.Flag(sshJWTCacheTTLFlag).Changed {
		ic.SSHJWTCacheTTL = &sshJWTCacheTTL
	}

	if cmd.Flag(interfaceNameFlag).Changed {
		if err := parseInterfaceName(interfaceName); err != nil {
			return nil, err
		}
		ic.InterfaceName = &interfaceName
	}

	if cmd.Flag(wireguardPortFlag).Changed {
		p := int(wireguardPort)
		ic.WireguardPort = &p
	}

	if cmd.Flag(mtuFlag).Changed {
		if err := iface.ValidateMTU(mtu); err != nil {
			return nil, err
		}
		ic.MTU = &mtu
	}

	if cmd.Flag(networkMonitorFlag).Changed {
		ic.NetworkMonitor = &networkMonitor
	}

	if cmd.Flag(disableAutoConnectFlag).Changed {
		ic.DisableAutoConnect = &autoConnectDisabled

		if autoConnectDisabled {
			cmd.Println("Autoconnect has been disabled. The client won't connect automatically when the service starts.")
		}

		if !autoConnectDisabled {
			cmd.Println("Autoconnect has been enabled. The client will connect automatically when the service starts.")
		}
	}

	if cmd.Flag(dnsRouteIntervalFlag).Changed {
		ic.DNSRouteInterval = &dnsRouteInterval
	}

	if cmd.Flag(disableClientRoutesFlag).Changed {
		ic.DisableClientRoutes = &disableClientRoutes
	}
	if cmd.Flag(disableServerRoutesFlag).Changed {
		ic.DisableServerRoutes = &disableServerRoutes
	}
	if cmd.Flag(disableDNSFlag).Changed {
		ic.DisableDNS = &disableDNS
	}
	if cmd.Flag(disableFirewallFlag).Changed {
		ic.DisableFirewall = &disableFirewall
	}

	if cmd.Flag(blockLANAccessFlag).Changed {
		ic.BlockLANAccess = &blockLANAccess
	}

	if cmd.Flag(blockInboundFlag).Changed {
		ic.BlockInbound = &blockInbound
	}

	if cmd.Flag(enableLazyConnectionFlag).Changed {
		ic.LazyConnectionEnabled = &lazyConnEnabled
	}
	return &ic, nil
}

func setupLoginRequestFromUpCmd(cmd *cobra.Command) (*proto.LoginRequest, error) {
	loginRequest := proto.LoginRequest{
		NatExternalIPs:      natExternalIPs,
		CleanNATExternalIPs: natExternalIPs != nil && len(natExternalIPs) == 0,
		ExtraIFaceBlacklist: extraIFaceBlackList,
		DnsLabels:           dnsLabelsValidated.ToPunycodeList(),
		CleanDNSLabels:      dnsLabels != nil && len(dnsLabels) == 0,
	}

	if cmd.Flag(dnsResolverAddress).Changed {
		var err error
		loginRequest.CustomDNSAddress, err = parseDNSAddress(customDNSAddress)
		if err != nil {
			return nil, err
		}
	}

	if cmd.Flag(enableRosenpassFlag).Changed {
		loginRequest.RosenpassEnabled = &rosenpassEnabled
	}

	if cmd.Flag(rosenpassPermissiveFlag).Changed {
		loginRequest.RosenpassPermissive = &rosenpassPermissive
	}

	if cmd.Flag(serverSSHAllowedFlag).Changed {
		loginRequest.ServerSSHAllowed = &serverSSHAllowed
	}

	if cmd.Flag(enableSSHRootFlag).Changed {
		loginRequest.EnableSSHRoot = &enableSSHRoot
	}

	if cmd.Flag(enableSSHSFTPFlag).Changed {
		loginRequest.EnableSSHSFTP = &enableSSHSFTP
	}

	if cmd.Flag(enableSSHLocalPortForwardFlag).Changed {
		loginRequest.EnableSSHLocalPortForwarding = &enableSSHLocalPortForward
	}

	if cmd.Flag(enableSSHRemotePortForwardFlag).Changed {
		loginRequest.EnableSSHRemotePortForwarding = &enableSSHRemotePortForward
	}

	if cmd.Flag(disableSSHAuthFlag).Changed {
		loginRequest.DisableSSHAuth = &disableSSHAuth
	}

	if cmd.Flag(sshJWTCacheTTLFlag).Changed {
		sshJWTCacheTTL32 := int32(sshJWTCacheTTL)
		loginRequest.SshJWTCacheTTL = &sshJWTCacheTTL32
	}

	if cmd.Flag(disableAutoConnectFlag).Changed {
		loginRequest.DisableAutoConnect = &autoConnectDisabled
	}

	if cmd.Flag(interfaceNameFlag).Changed {
		if err := parseInterfaceName(interfaceName); err != nil {
			return nil, err
		}
		loginRequest.InterfaceName = &interfaceName
	}

	if cmd.Flag(wireguardPortFlag).Changed {
		wp := int64(wireguardPort)
		loginRequest.WireguardPort = &wp
	}

	if cmd.Flag(mtuFlag).Changed {
		if err := iface.ValidateMTU(mtu); err != nil {
			return nil, err
		}
		m := int64(mtu)
		loginRequest.Mtu = &m
	}

	if cmd.Flag(networkMonitorFlag).Changed {
		loginRequest.NetworkMonitor = &networkMonitor
	}

	if cmd.Flag(dnsRouteIntervalFlag).Changed {
		loginRequest.DnsRouteInterval = durationpb.New(dnsRouteInterval)
	}

	if cmd.Flag(disableClientRoutesFlag).Changed {
		loginRequest.DisableClientRoutes = &disableClientRoutes
	}
	if cmd.Flag(disableServerRoutesFlag).Changed {
		loginRequest.DisableServerRoutes = &disableServerRoutes
	}
	if cmd.Flag(disableDNSFlag).Changed {
		loginRequest.DisableDns = &disableDNS
	}
	if cmd.Flag(disableFirewallFlag).Changed {
		loginRequest.DisableFirewall = &disableFirewall
	}

	if cmd.Flag(blockLANAccessFlag).Changed {
		loginRequest.BlockLanAccess = &blockLANAccess
	}

	if cmd.Flag(blockInboundFlag).Changed {
		loginRequest.BlockInbound = &blockInbound
	}

	if cmd.Flag(enableLazyConnectionFlag).Changed {
		loginRequest.LazyConnectionEnabled = &lazyConnEnabled
	}
	return &loginRequest, nil
}

func validateNATExternalIPs(list []string) error {
	for _, element := range list {
		if element == "" {
			return fmt.Errorf("empty string is not a valid input for %s", externalIPMapFlag)
		}

		subElements := strings.Split(element, "/")
		if len(subElements) > 2 {
			return fmt.Errorf("%s is not a valid input for %s. it should be formatted as \"String\" or \"String/String\"", element, externalIPMapFlag)
		}

		if len(subElements) == 1 && !isValidIP(subElements[0]) {
			return fmt.Errorf("%s is not a valid input for %s. it should be formatted as \"IP\" or \"IP/IP\", or \"IP/Interface Name\"", element, externalIPMapFlag)
		}

		last := 0
		for _, singleElement := range subElements {
			inputType, err := validateElement(singleElement)
			if err != nil {
				return fmt.Errorf("%s is not a valid input for %s. it should be an IP string or a network name", singleElement, externalIPMapFlag)
			}
			if last == interfaceInputType && inputType == interfaceInputType {
				return fmt.Errorf("%s is not a valid input for %s. it should not contain two interface names", element, externalIPMapFlag)
			}
			last = inputType
		}
	}
	return nil
}

func parseInterfaceName(name string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	if strings.HasPrefix(name, "utun") {
		return nil
	}

	return fmt.Errorf("invalid interface name %s. Please use the prefix utun followed by a number on MacOS. e.g., utun1 or utun199", name)
}

func validateElement(element string) (int, error) {
	if isValidIP(element) {
		return ipInputType, nil
	}
	validIface, err := isValidInterface(element)
	if err != nil {
		return invalidInputType, fmt.Errorf("unable to validate the network interface name, error: %s", err)
	}

	if validIface {
		return interfaceInputType, nil
	}

	return interfaceInputType, fmt.Errorf("invalid IP or network interface name not found")
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isValidInterface(name string) (bool, error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, iface := range netInterfaces {
		if iface.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func parseDNSAddress(dnsAddress string) ([]byte, error) {
	var parsed []byte
	if !isValidAddrPort(dnsAddress) {
		return nil, fmt.Errorf("%s is invalid, it should be formatted as IP:Port string or as an empty string like \"\"", dnsAddress)
	}
	if dnsAddress == "" && util.FindFirstLogPath(logFiles) != "" {
		parsed = []byte("empty")
	} else {
		parsed = []byte(dnsAddress)
	}
	return parsed, nil
}

func validateDnsLabels(labels []string) (domain.List, error) {
	var (
		domains domain.List
		err     error
	)

	if len(labels) == 0 {
		return domains, nil
	}

	domains, err = domain.ValidateDomains(labels)
	if err != nil {
		return nil, fmt.Errorf("failed to validate dns labels: %v", err)
	}

	return domains, nil
}

func isValidAddrPort(input string) bool {
	if input == "" {
		return true
	}
	_, err := netip.ParseAddrPort(input)
	return err == nil
}
