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
	"google.golang.org/grpc/codes"

	gstatus "google.golang.org/grpc/status"
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
	dnsLabelsFlag = "extra-dns-labels"

	noBrowserFlag = "no-browser"
	noBrowserDesc = "do not open the browser for SSO login"

	profileNameFlag = "profile"
	profileNameDesc = "profile name to use for the login. If not specified, the last used profile will be used."
)

var (
	foregroundMode     bool
	dnsLabels          []string
	dnsLabelsValidated domain.List
	noBrowser          bool
	profileName        string
	configPath         string

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

	var profileSwitched bool
	// switch profile if provided
	if profileName != "" {
		err = switchProfile(cmd.Context(), profileName, username.Username)
		if err != nil {
			return fmt.Errorf("switch profile: %v", err)
		}

		err = pm.SwitchProfile(profileName)
		if err != nil {
			return fmt.Errorf("switch profile: %v", err)
		}

		profileSwitched = true
	}

	activeProf, err := pm.GetActiveProfile()
	if err != nil {
		return fmt.Errorf("get active profile: %v", err)
	}

	if foregroundMode {
		return runInForegroundMode(ctx, cmd, activeProf)
	}
	return runInDaemonMode(ctx, cmd, pm, activeProf, profileSwitched)
}

func runInForegroundMode(ctx context.Context, cmd *cobra.Command, activeProf *profilemanager.Profile) error {
	// override the default profile filepath if provided
	if isFlagChanged(cmd, "config") && configPath != "" {
		_ = profilemanager.NewServiceManager(configPath)
	}

	err := handleRebrand(cmd)
	if err != nil {
		return err
	}

	customDNSAddressConverted, err := parseCustomDNSAddress(isFlagChanged(cmd, dnsResolverAddress))
	if err != nil {
		return err
	}

	configFilePath, err := activeProf.FilePath()
	if err != nil {
		return fmt.Errorf("get active profile file path: %v", err)
	}

	ic, err := setupConfig(customDNSAddressConverted, cmd, configFilePath)
	if err != nil {
		return fmt.Errorf("setup config: %v", err)
	}

	providedSetupKey, err := getSetupKey()
	if err != nil {
		return err
	}

	config, err := profilemanager.UpdateOrCreateConfig(*ic)
	if err != nil {
		return fmt.Errorf("get config file: %v", err)
	}

	_, _ = profilemanager.UpdateOldManagementURL(ctx, config, configFilePath)

	err = foregroundLogin(ctx, cmd, config, providedSetupKey, activeProf.Name)
	if err != nil {
		return fmt.Errorf("foreground login failed: %v", err)
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
	// Check if deprecated config flag is set and show warning
	if cmd.Flag("config").Changed && configPath != "" {
		cmd.PrintErrf("Warning: Config flag is deprecated on up command, it should be set as a service argument with $NB_CONFIG environment or with \"-config\" flag; netbird service reconfigure --service-env=\"NB_CONFIG=<file_path>\" or netbird service run --config=<file_path>\n")
	}

	customDNSAddressConverted, err := parseCustomDNSAddress(cmd.Flag(dnsResolverAddress).Changed)
	if err != nil {
		return fmt.Errorf("parse custom DNS address: %v", err)
	}

	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		//nolint
		return fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Warnf("failed closing daemon gRPC client connection %v", err)
			return
		}
	}()

	client := proto.NewDaemonServiceClient(conn)

	status, err := client.Status(ctx, &proto.StatusRequest{
		WaitForReady: func() *bool { b := true; return &b }(),
	})
	if err != nil {
		return fmt.Errorf("unable to get daemon status: %v", err)
	}

	if status.Status == string(internal.StatusConnected) {
		if !profileSwitched {
			cmd.Println("Already connected")
			return nil
		}

		if _, err := client.Down(ctx, &proto.DownRequest{}); err != nil {
			log.Errorf("call service down method: %v", err)
			return err
		}
	}

	username, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %v", err)
	}

	// set the new config
	req := setupSetConfigReq(customDNSAddressConverted, cmd, activeProf.Name, username.Username)
	if _, err := client.SetConfig(ctx, req); err != nil {
		if st, ok := gstatus.FromError(err); ok && st.Code() == codes.Unavailable {
			log.Warnf("setConfig method is not available in the daemon")
		} else {
			return fmt.Errorf("call service setConfig method: %v", err)
		}
	}

	if err := doDaemonUp(ctx, cmd, client, pm, activeProf, customDNSAddressConverted, username.Username); err != nil {
		return fmt.Errorf("daemon up failed: %v", err)
	}
	cmd.Println("Connected")
	return nil
}

func doDaemonUp(ctx context.Context, cmd *cobra.Command, client proto.DaemonServiceClient, pm *profilemanager.ProfileManager, activeProf *profilemanager.Profile, customDNSAddressConverted []byte, username string) error {

	providedSetupKey, err := getSetupKey()
	if err != nil {
		return fmt.Errorf("get setup key: %v", err)
	}

	loginRequest, err := setupLoginRequest(providedSetupKey, customDNSAddressConverted, cmd)
	if err != nil {
		return fmt.Errorf("setup login request: %v", err)
	}

	loginRequest.ProfileName = &activeProf.Name
	loginRequest.Username = &username

	profileState, err := pm.GetProfileState(activeProf.Name)
	if err != nil {
		log.Debugf("failed to get profile state for login hint: %v", err)
	} else if profileState.Email != "" {
		loginRequest.Hint = &profileState.Email
	}

	var loginErr error
	var loginResp *proto.LoginResponse

	err = WithBackOff(func() error {
		var backOffErr error
		loginResp, backOffErr = client.Login(ctx, loginRequest)
		if s, ok := gstatus.FromError(backOffErr); ok && (s.Code() == codes.InvalidArgument ||
			s.Code() == codes.PermissionDenied ||
			s.Code() == codes.NotFound ||
			s.Code() == codes.Unimplemented) {
			loginErr = backOffErr
			return nil
		}
		return backOffErr
	})
	if err != nil {
		return fmt.Errorf("login backoff cycle failed: %v", err)
	}

	if loginErr != nil {
		return fmt.Errorf("login failed: %v", loginErr)
	}

	if loginResp.NeedsSSOLogin {
		if err := handleSSOLogin(ctx, cmd, loginResp, client, pm); err != nil {
			return fmt.Errorf("sso login failed: %v", err)
		}
	}

	if _, err := client.Up(ctx, &proto.UpRequest{
		ProfileName: &activeProf.Name,
		Username:    &username,
	}); err != nil {
		return fmt.Errorf("call service up method: %v", err)
	}

	return nil
}

func setupSetConfigReq(customDNSAddressConverted []byte, cmd *cobra.Command, profileName, username string) *proto.SetConfigRequest {
	var req proto.SetConfigRequest
	req.ProfileName = profileName
	req.Username = username

	if rootCmd.PersistentFlags().Changed("management-url") {
		req.ManagementUrl = managementURL
	}
	if rootCmd.PersistentFlags().Changed("admin-url") {
		req.AdminURL = adminURL
	}
	req.NatExternalIPs = natExternalIPs
	req.CustomDNSAddress = customDNSAddressConverted
	req.ExtraIFaceBlacklist = extraIFaceBlackList
	req.DnsLabels = dnsLabelsValidated.ToPunycodeList()
	req.CleanDNSLabels = dnsLabels != nil && len(dnsLabels) == 0
	req.CleanNATExternalIPs = natExternalIPs != nil && len(natExternalIPs) == 0

	if isFlagChanged(cmd, enableRosenpassFlag) {
		req.RosenpassEnabled = &rosenpassEnabled
	}
	if isFlagChanged(cmd, rosenpassPermissiveFlag) {
		req.RosenpassPermissive = &rosenpassPermissive
	}
	if isFlagChanged(cmd, serverSSHAllowedFlag) {
		req.ServerSSHAllowed = &serverSSHAllowed
	}
	if isFlagChanged(cmd, enableSSHRootFlag) {
		req.EnableSSHRoot = &enableSSHRoot
	}
	if isFlagChanged(cmd, enableSSHSFTPFlag) {
		req.EnableSSHSFTP = &enableSSHSFTP
	}
	if isFlagChanged(cmd, enableSSHLocalPortForwardFlag) {
		req.EnableSSHLocalPortForwarding = &enableSSHLocalPortForward
	}
	if isFlagChanged(cmd, enableSSHRemotePortForwardFlag) {
		req.EnableSSHRemotePortForwarding = &enableSSHRemotePortForward
	}
	if isFlagChanged(cmd, disableSSHAuthFlag) {
		req.DisableSSHAuth = &disableSSHAuth
	}
	if isFlagChanged(cmd, sshJWTCacheTTLFlag) {
		sshJWTCacheTTL32 := int32(sshJWTCacheTTL)
		req.SshJWTCacheTTL = &sshJWTCacheTTL32
	}
	if isFlagChanged(cmd, interfaceNameFlag) {
		if err := parseInterfaceName(interfaceName); err != nil {
			log.Errorf("parse interface name: %v", err)
			return nil
		}
		req.InterfaceName = &interfaceName
	}
	if isFlagChanged(cmd, wireguardPortFlag) {
		p := int64(wireguardPort)
		req.WireguardPort = &p
	}

	if isFlagChanged(cmd, mtuFlag) {
		m := int64(mtu)
		req.Mtu = &m
	}

	if isFlagChanged(cmd, networkMonitorFlag) {
		req.NetworkMonitor = &networkMonitor
	}
	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		req.OptionalPreSharedKey = &preSharedKey
	}
	if isFlagChanged(cmd, disableAutoConnectFlag) {
		req.DisableAutoConnect = &autoConnectDisabled
	}

	if isFlagChanged(cmd, dnsRouteIntervalFlag) {
		req.DnsRouteInterval = durationpb.New(dnsRouteInterval)
	}

	if isFlagChanged(cmd, disableClientRoutesFlag) {
		req.DisableClientRoutes = &disableClientRoutes
	}

	if isFlagChanged(cmd, disableServerRoutesFlag) {
		req.DisableServerRoutes = &disableServerRoutes
	}

	if isFlagChanged(cmd, disableDNSFlag) {
		req.DisableDns = &disableDNS
	}

	if isFlagChanged(cmd, disableFirewallFlag) {
		req.DisableFirewall = &disableFirewall
	}

	if isFlagChanged(cmd, blockLANAccessFlag) {
		req.BlockLanAccess = &blockLANAccess
	}

	if isFlagChanged(cmd, blockInboundFlag) {
		req.BlockInbound = &blockInbound
	}

	if isFlagChanged(cmd, enableLazyConnectionFlag) {
		req.LazyConnectionEnabled = &lazyConnEnabled
	}

	return &req
}

func setupConfig(customDNSAddressConverted []byte, cmd *cobra.Command, configFilePath string) (*profilemanager.ConfigInput, error) {
	ic := profilemanager.ConfigInput{
		ManagementURL:       managementURL,
		ConfigPath:          configFilePath,
		NATExternalIPs:      natExternalIPs,
		CustomDNSAddress:    customDNSAddressConverted,
		ExtraIFaceBlackList: extraIFaceBlackList,
		DNSLabels:           dnsLabelsValidated,
	}

	if isFlagChanged(cmd, enableRosenpassFlag) {
		ic.RosenpassEnabled = &rosenpassEnabled
	}

	if isFlagChanged(cmd, rosenpassPermissiveFlag) {
		ic.RosenpassPermissive = &rosenpassPermissive
	}

	if isFlagChanged(cmd, serverSSHAllowedFlag) {
		ic.ServerSSHAllowed = &serverSSHAllowed
	}

	if isFlagChanged(cmd, enableSSHRootFlag) {
		ic.EnableSSHRoot = &enableSSHRoot
	}

	if isFlagChanged(cmd, enableSSHSFTPFlag) {
		ic.EnableSSHSFTP = &enableSSHSFTP
	}

	if isFlagChanged(cmd, enableSSHLocalPortForwardFlag) {
		ic.EnableSSHLocalPortForwarding = &enableSSHLocalPortForward
	}

	if isFlagChanged(cmd, enableSSHRemotePortForwardFlag) {
		ic.EnableSSHRemotePortForwarding = &enableSSHRemotePortForward
	}

	if isFlagChanged(cmd, disableSSHAuthFlag) {
		ic.DisableSSHAuth = &disableSSHAuth
	}

	if isFlagChanged(cmd, sshJWTCacheTTLFlag) {
		ic.SSHJWTCacheTTL = &sshJWTCacheTTL
	}

	if isFlagChanged(cmd, interfaceNameFlag) {
		if err := parseInterfaceName(interfaceName); err != nil {
			return nil, err
		}
		ic.InterfaceName = &interfaceName
	}

	if isFlagChanged(cmd, wireguardPortFlag) {
		p := int(wireguardPort)
		ic.WireguardPort = &p
	}

	if isFlagChanged(cmd, mtuFlag) {
		if err := iface.ValidateMTU(mtu); err != nil {
			return nil, err
		}
		ic.MTU = &mtu
	}

	if isFlagChanged(cmd, networkMonitorFlag) {
		ic.NetworkMonitor = &networkMonitor
	}

	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		ic.PreSharedKey = &preSharedKey
	}

	if isFlagChanged(cmd, disableAutoConnectFlag) {
		ic.DisableAutoConnect = &autoConnectDisabled

		if autoConnectDisabled {
			cmd.Println("Autoconnect has been disabled. The client won't connect automatically when the service starts.")
		}

		if !autoConnectDisabled {
			cmd.Println("Autoconnect has been enabled. The client will connect automatically when the service starts.")
		}
	}

	if isFlagChanged(cmd, dnsRouteIntervalFlag) {
		ic.DNSRouteInterval = &dnsRouteInterval
	}

	if isFlagChanged(cmd, disableClientRoutesFlag) {
		ic.DisableClientRoutes = &disableClientRoutes
	}
	if isFlagChanged(cmd, disableServerRoutesFlag) {
		ic.DisableServerRoutes = &disableServerRoutes
	}
	if isFlagChanged(cmd, disableDNSFlag) {
		ic.DisableDNS = &disableDNS
	}
	if isFlagChanged(cmd, disableFirewallFlag) {
		ic.DisableFirewall = &disableFirewall
	}

	if isFlagChanged(cmd, blockLANAccessFlag) {
		ic.BlockLANAccess = &blockLANAccess
	}

	if isFlagChanged(cmd, blockInboundFlag) {
		ic.BlockInbound = &blockInbound
	}

	if isFlagChanged(cmd, enableLazyConnectionFlag) {
		ic.LazyConnectionEnabled = &lazyConnEnabled
	}
	return &ic, nil
}

func setupLoginRequest(providedSetupKey string, customDNSAddressConverted []byte, cmd *cobra.Command) (*proto.LoginRequest, error) {
	loginRequest := proto.LoginRequest{
		SetupKey:            providedSetupKey,
		NatExternalIPs:      natExternalIPs,
		CleanNATExternalIPs: natExternalIPs != nil && len(natExternalIPs) == 0,
		CustomDNSAddress:    customDNSAddressConverted,
		IsUnixDesktopClient: isUnixRunningDesktop(),
		Hostname:            hostName,
		ExtraIFaceBlacklist: extraIFaceBlackList,
		DnsLabels:           dnsLabels,
		CleanDNSLabels:      dnsLabels != nil && len(dnsLabels) == 0,
	}

	if rootCmd.PersistentFlags().Changed("management-url") {
		loginRequest.ManagementUrl = managementURL
	}

	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		loginRequest.OptionalPreSharedKey = &preSharedKey
	}

	if isFlagChanged(cmd, enableRosenpassFlag) {
		loginRequest.RosenpassEnabled = &rosenpassEnabled
	}

	if isFlagChanged(cmd, rosenpassPermissiveFlag) {
		loginRequest.RosenpassPermissive = &rosenpassPermissive
	}

	if isFlagChanged(cmd, serverSSHAllowedFlag) {
		loginRequest.ServerSSHAllowed = &serverSSHAllowed
	}

	if isFlagChanged(cmd, enableSSHRootFlag) {
		loginRequest.EnableSSHRoot = &enableSSHRoot
	}

	if isFlagChanged(cmd, enableSSHSFTPFlag) {
		loginRequest.EnableSSHSFTP = &enableSSHSFTP
	}

	if isFlagChanged(cmd, enableSSHLocalPortForwardFlag) {
		loginRequest.EnableSSHLocalPortForwarding = &enableSSHLocalPortForward
	}

	if isFlagChanged(cmd, enableSSHRemotePortForwardFlag) {
		loginRequest.EnableSSHRemotePortForwarding = &enableSSHRemotePortForward
	}

	if isFlagChanged(cmd, disableSSHAuthFlag) {
		loginRequest.DisableSSHAuth = &disableSSHAuth
	}

	if isFlagChanged(cmd, sshJWTCacheTTLFlag) {
		sshJWTCacheTTL32 := int32(sshJWTCacheTTL)
		loginRequest.SshJWTCacheTTL = &sshJWTCacheTTL32
	}

	if isFlagChanged(cmd, disableAutoConnectFlag) {
		loginRequest.DisableAutoConnect = &autoConnectDisabled
	}

	if isFlagChanged(cmd, interfaceNameFlag) {
		if err := parseInterfaceName(interfaceName); err != nil {
			return nil, err
		}
		loginRequest.InterfaceName = &interfaceName
	}

	if isFlagChanged(cmd, wireguardPortFlag) {
		wp := int64(wireguardPort)
		loginRequest.WireguardPort = &wp
	}

	if isFlagChanged(cmd, mtuFlag) {
		if err := iface.ValidateMTU(mtu); err != nil {
			return nil, err
		}
		m := int64(mtu)
		loginRequest.Mtu = &m
	}

	if isFlagChanged(cmd, networkMonitorFlag) {
		loginRequest.NetworkMonitor = &networkMonitor
	}

	if isFlagChanged(cmd, dnsRouteIntervalFlag) {
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

func parseCustomDNSAddress(modified bool) ([]byte, error) {
	var parsed []byte
	if modified {
		if !isValidAddrPort(customDNSAddress) {
			return nil, fmt.Errorf("%s is invalid, it should be formatted as IP:Port string or as an empty string like \"\"", customDNSAddress)
		}
		if customDNSAddress == "" && util.FindFirstLogPath(logFiles) != "" {
			parsed = []byte("empty")
		} else {
			parsed = []byte(customDNSAddress)
		}
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

func isFlagChanged(cmd *cobra.Command, name string) bool {
	flag := cmd.Flag(name)
	if flag == nil {
		return false
	}
	return flag.Changed
}
