package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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
	"github.com/netbirdio/netbird/management/domain"
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

	upCmd = &cobra.Command{
		Use:   "up",
		Short: "install, login and start Netbird client",
		RunE:  upFunc,
	}
)

func init() {
	upCmd.PersistentFlags().BoolVarP(&foregroundMode, "foreground-mode", "F", false, "start service in foreground")
	upCmd.PersistentFlags().StringVar(&interfaceName, interfaceNameFlag, iface.WgInterfaceDefault, "Wireguard interface name")
	upCmd.PersistentFlags().Uint16Var(&wireguardPort, wireguardPortFlag, iface.DefaultWgPort, "Wireguard interface listening port")
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

}

func upFunc(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)

	cmd.SetOut(cmd.OutOrStdout())

	err := util.InitLog(logLevel, "console")
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
	activeProf, err := pm.GetActiveProfile()
	if err != nil {
		return fmt.Errorf("get active profile: %v", err)
	}

	var profileSwitched bool
	// switch profile if provided
	if profileName != "" && activeProf.Name != profileName {
		err = pm.SwitchProfile(profileName)
		if err != nil {
			return fmt.Errorf("switch profile: %v", err)
		}

		err = switchProfile(cmd.Context(), activeProf)
		if err != nil {
			return fmt.Errorf("switch profile: %v", err)
		}

		profileSwitched = true
	}

	activeProf, err = pm.GetActiveProfile()
	if err != nil {
		return fmt.Errorf("get active profile: %v", err)
	}

	if foregroundMode {
		return runInForegroundMode(ctx, cmd, activeProf)
	}
	return runInDaemonMode(ctx, cmd, pm, activeProf, profileSwitched)
}

func runInForegroundMode(ctx context.Context, cmd *cobra.Command, activeProf *profilemanager.Profile) error {
	err := handleRebrand(cmd, activeProf)
	if err != nil {
		return err
	}

	customDNSAddressConverted, err := parseCustomDNSAddress(cmd.Flag(dnsResolverAddress).Changed)
	if err != nil {
		return err
	}

	configPath, err := activeProf.FilePath()
	if err != nil {
		return fmt.Errorf("get active profile path: %v", err)
	}

	ic, err := setupConfig(customDNSAddressConverted, cmd, configPath)
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

	_, _ = profilemanager.UpdateOldManagementURL(ctx, config, configPath)

	err = foregroundLogin(ctx, cmd, config, providedSetupKey)
	if err != nil {
		return fmt.Errorf("foreground login failed: %v", err)
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	SetupCloseHandler(ctx, cancel)

	r := peer.NewRecorder(config.ManagementURL.String())
	r.GetFullStatus()

	connectClient := internal.NewConnectClient(ctx, config, r)
	SetupDebugHandler(ctx, config, r, connectClient, "")

	return connectClient.Run(nil)
}

func runInDaemonMode(ctx context.Context, cmd *cobra.Command, pm *profilemanager.ProfileManager, activeProf *profilemanager.Profile, profileSwitched bool) error {
	customDNSAddressConverted, configPath, err := prepareConfig(ctx, cmd, activeProf)
	if err != nil {
		return fmt.Errorf("prepare config: %v", err)
	}

	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
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

	status, err := client.Status(ctx, &proto.StatusRequest{})
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

	if err := doDaemonUp(ctx, cmd, client, pm, activeProf, configPath, customDNSAddressConverted); err != nil {
		return fmt.Errorf("daemon up failed: %v", err)
	}
	cmd.Println("Connected")
	return nil
}

func doDaemonUp(ctx context.Context, cmd *cobra.Command, client proto.DaemonServiceClient, pm *profilemanager.ProfileManager, activeProf *profilemanager.Profile, configPath string, customDNSAddressConverted []byte) error {

	providedSetupKey, err := getSetupKey()
	if err != nil {
		return fmt.Errorf("get setup key: %v", err)
	}

	loginRequest, err := setupLoginRequest(providedSetupKey, customDNSAddressConverted, cmd)
	if err != nil {
		return fmt.Errorf("setup login request: %v", err)
	}

	loginRequest.ProfileName = &activeProf.Name
	loginRequest.ProfilePath = &configPath

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
		ProfilePath: &configPath,
	}); err != nil {
		return fmt.Errorf("call service up method: %v", err)
	}

	return nil
}

func prepareConfig(ctx context.Context, cmd *cobra.Command, activeProf *profilemanager.Profile) ([]byte, string, error) {
	customDNSAddressConverted, err := parseCustomDNSAddress(cmd.Flag(dnsResolverAddress).Changed)
	if err != nil {
		return []byte{}, "", fmt.Errorf("parse custom DNS address: %v", err)
	}

	configPath, err := activeProf.FilePath()
	if err != nil {
		return nil, "", fmt.Errorf("get active profile path: %v", err)
	}

	if activeProf.Name != "default" {
		ic, err := setupConfig(customDNSAddressConverted, cmd, configPath)
		if err != nil {
			return nil, "", fmt.Errorf("setup config: %v", err)
		}

		config, err := profilemanager.UpdateOrCreateConfig(*ic)
		if err != nil {
			return nil, "", fmt.Errorf("get config file: %v", err)
		}

		_, _ = profilemanager.UpdateOldManagementURL(ctx, config, configPath)
	}

	return customDNSAddressConverted, configPath, nil

}

func setupConfig(customDNSAddressConverted []byte, cmd *cobra.Command, configPath string) (*profilemanager.ConfigInput, error) {
	ic := profilemanager.ConfigInput{
		ManagementURL:       managementURL,
		AdminURL:            adminURL,
		ConfigPath:          configPath,
		NATExternalIPs:      natExternalIPs,
		CustomDNSAddress:    customDNSAddressConverted,
		ExtraIFaceBlackList: extraIFaceBlackList,
		DNSLabels:           dnsLabelsValidated,
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

	if cmd.Flag(networkMonitorFlag).Changed {
		ic.NetworkMonitor = &networkMonitor
	}

	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		ic.PreSharedKey = &preSharedKey
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

func setupLoginRequest(providedSetupKey string, customDNSAddressConverted []byte, cmd *cobra.Command) (*proto.LoginRequest, error) {
	loginRequest := proto.LoginRequest{
		SetupKey:            providedSetupKey,
		ManagementUrl:       managementURL,
		AdminURL:            adminURL,
		NatExternalIPs:      natExternalIPs,
		CleanNATExternalIPs: natExternalIPs != nil && len(natExternalIPs) == 0,
		CustomDNSAddress:    customDNSAddressConverted,
		IsUnixDesktopClient: isUnixRunningDesktop(),
		Hostname:            hostName,
		ExtraIFaceBlacklist: extraIFaceBlackList,
		DnsLabels:           dnsLabels,
		CleanDNSLabels:      dnsLabels != nil && len(dnsLabels) == 0,
	}

	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		loginRequest.OptionalPreSharedKey = &preSharedKey
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

func parseCustomDNSAddress(modified bool) ([]byte, error) {
	var parsed []byte
	if modified {
		if !isValidAddrPort(customDNSAddress) {
			return nil, fmt.Errorf("%s is invalid, it should be formatted as IP:Port string or as an empty string like \"\"", customDNSAddress)
		}
		if customDNSAddress == "" && logFile != "console" {
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
