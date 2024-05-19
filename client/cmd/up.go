package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/util"
)

const (
	invalidInputType int = iota
	ipInputType
	interfaceInputType
)

var (
	foregroundMode bool
	upCmd          = &cobra.Command{
		Use:   "up",
		Short: "install, login and start Netbird client",
		RunE:  upFunc,
	}
)

func init() {
	upCmd.PersistentFlags().BoolVarP(&foregroundMode, "foreground-mode", "F", false, "start service in foreground")
	upCmd.PersistentFlags().StringVar(&interfaceName, interfaceNameFlag, iface.WgInterfaceDefault, "Wireguard interface name")
	upCmd.PersistentFlags().Uint16Var(&wireguardPort, wireguardPortFlag, iface.DefaultWgPort, "Wireguard interface listening port")
	upCmd.PersistentFlags().BoolVarP(&networkMonitor, networkMonitorFlag, "N", false, "Enable network monitoring")
	upCmd.PersistentFlags().StringSliceVar(&extraIFaceBlackList, extraIFaceBlackListFlag, nil, "Extra list of default interfaces to ignore for listening")
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

	ctx := internal.CtxInitState(cmd.Context())

	if hostName != "" {
		// nolint
		ctx = context.WithValue(ctx, system.DeviceNameCtxKey, hostName)
	}

	if foregroundMode {
		return runInForegroundMode(ctx, cmd)
	}
	return runInDaemonMode(ctx, cmd)
}

func runInForegroundMode(ctx context.Context, cmd *cobra.Command) error {
	err := handleRebrand(cmd)
	if err != nil {
		return err
	}

	customDNSAddressConverted, err := parseCustomDNSAddress(cmd.Flag(dnsResolverAddress).Changed)
	if err != nil {
		return err
	}

	ic := internal.ConfigInput{
		ManagementURL:       managementURL,
		AdminURL:            adminURL,
		ConfigPath:          configPath,
		NATExternalIPs:      natExternalIPs,
		CustomDNSAddress:    customDNSAddressConverted,
		ExtraIFaceBlackList: extraIFaceBlackList,
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
			return err
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

	config, err := internal.UpdateOrCreateConfig(ic)
	if err != nil {
		return fmt.Errorf("get config file: %v", err)
	}

	config, _ = internal.UpdateOldManagementURL(ctx, config, configPath)

	err = foregroundLogin(ctx, cmd, config, setupKey)
	if err != nil {
		return fmt.Errorf("foreground login failed: %v", err)
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	SetupCloseHandler(ctx, cancel)

	connectClient := internal.NewConnectClient(ctx, config, peer.NewRecorder(config.ManagementURL.String()))
	return connectClient.Run()
}

func runInDaemonMode(ctx context.Context, cmd *cobra.Command) error {
	customDNSAddressConverted, err := parseCustomDNSAddress(cmd.Flag(dnsResolverAddress).Changed)
	if err != nil {
		return err
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
		cmd.Println("Already connected")
		return nil
	}

	loginRequest := proto.LoginRequest{
		SetupKey:             setupKey,
		ManagementUrl:        managementURL,
		AdminURL:             adminURL,
		NatExternalIPs:       natExternalIPs,
		CleanNATExternalIPs:  natExternalIPs != nil && len(natExternalIPs) == 0,
		CustomDNSAddress:     customDNSAddressConverted,
		IsLinuxDesktopClient: isLinuxRunningDesktop(),
		Hostname:             hostName,
		ExtraIFaceBlacklist:  extraIFaceBlackList,
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
			return err
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

	var loginErr error

	var loginResp *proto.LoginResponse

	err = WithBackOff(func() error {
		var backOffErr error
		loginResp, backOffErr = client.Login(ctx, &loginRequest)
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

		openURL(cmd, loginResp.VerificationURIComplete, loginResp.UserCode)

		_, err = client.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode, Hostname: hostName})
		if err != nil {
			return fmt.Errorf("waiting sso login failed with: %v", err)
		}
	}

	if _, err := client.Up(ctx, &proto.UpRequest{}); err != nil {
		return fmt.Errorf("call service up method: %v", err)
	}
	cmd.Println("Connected")
	return nil
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

func isValidAddrPort(input string) bool {
	if input == "" {
		return true
	}
	_, err := netip.ParseAddrPort(input)
	return err == nil
}
