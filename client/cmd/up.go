package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
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
	upCmd.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "Netbird config file location")
	upCmd.PersistentFlags().StringVar(&adminURL, "admin-url", "", fmt.Sprintf("Admin Panel URL [http|https]://[host]:[port] (default \"%s\")", internal.DefaultAdminURL))
	upCmd.PersistentFlags().StringVarP(&managementURL, "management-url", "m", "", fmt.Sprintf("Management Service URL [http|https]://[host]:[port] (default \"%s\")", internal.DefaultManagementURL))
	upCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "sets Netbird log level")
	upCmd.PersistentFlags().StringVar(&logFile, "log-file", defaultLogFile, "sets Netbird log path. If console is specified the the log will be output to stdout")
	upCmd.PersistentFlags().BoolVarP(&foregroundMode, "foreground-mode", "F", false, "start service in foreground")
	upCmd.PersistentFlags().StringVar(&daemonAddr, "daemon-addr", defaultDaemonAddr, "Daemon service address to serve CLI requests [unix|tcp]://[path|host:port]")
	upCmd.PersistentFlags().StringVarP(&hostName, "hostname", "n", "", "Sets a custom hostname for the device")
	upCmd.PersistentFlags().StringVar(&preSharedKey, "preshared-key", "", "Sets Wireguard PreSharedKey property. If set, then only peers that have the same key can communicate.")
	upCmd.PersistentFlags().StringVarP(&setupKey, "setup-key", "k", "", "Setup key obtained from the Management Service Dashboard (used to register peer)")
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
		ManagementURL:    managementURL,
		AdminURL:         adminURL,
		ConfigPath:       configPath,
		NATExternalIPs:   natExternalIPs,
		CustomDNSAddress: customDNSAddressConverted,
	}
	if preSharedKey != "" {
		ic.PreSharedKey = &preSharedKey
	}

	config, err := internal.UpdateOrCreateConfig(ic)
	if err != nil {
		return fmt.Errorf("get config file: %v", err)
	}

	config, _ = internal.UpdateOldManagementPort(ctx, config, configPath)

	err = foregroundLogin(ctx, cmd, config, setupKey)
	if err != nil {
		return fmt.Errorf("foreground login failed: %v", err)
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	SetupCloseHandler(ctx, cancel)
	return internal.RunClient(ctx, config, peer.NewRecorder(config.ManagementURL.String()), nil, nil)
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
			log.Warnf("failed closing dameon gRPC client connection %v", err)
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
		SetupKey:            setupKey,
		PreSharedKey:        preSharedKey,
		ManagementUrl:       managementURL,
		AdminURL:            adminURL,
		NatExternalIPs:      natExternalIPs,
		CleanNATExternalIPs: natExternalIPs != nil && len(natExternalIPs) == 0,
		CustomDNSAddress:    customDNSAddressConverted,
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

		_, err = client.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode})
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
			return fmt.Errorf("%s is not a valid input for %s. it should be formated as \"String\" or \"String/String\"", element, externalIPMapFlag)
		}

		if len(subElements) == 1 && !isValidIP(subElements[0]) {
			return fmt.Errorf("%s is not a valid input for %s. it should be formated as \"IP\" or \"IP/IP\", or \"IP/Interface Name\"", element, externalIPMapFlag)
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
			return nil, fmt.Errorf("%s is invalid, it should be formated as IP:Port string or as an empty string like \"\"", customDNSAddress)
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
