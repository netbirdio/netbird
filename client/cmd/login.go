package cmd

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/util"
)

func init() {
	loginCmd.PersistentFlags().BoolVar(&noBrowser, noBrowserFlag, false, noBrowserDesc)
	loginCmd.PersistentFlags().StringVar(&profileName, profileNameFlag, "", profileNameDesc)
	loginCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "(DEPRECATED) Netbird config file location")
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to the NetBird network",
	Long:  "Log in to the NetBird network using a setup key or SSO",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := setEnvAndFlags(cmd); err != nil {
			return fmt.Errorf("set env and flags: %v", err)
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
		activeProf, err := getActiveProfile(ctx, pm, profileName, username.Username)
		if err != nil {
			return fmt.Errorf("get active profile: %v", err)
		}

		// foreground mode
		if util.FindFirstLogPath(logFiles) == "" {
			if _, err := doForegroundLogin(ctx, cmd, activeProf, &profilemanager.ConfigInput{}); err != nil {
				return fmt.Errorf("foreground login failed: %v", err)
			}
		} else { // daemon mode
			// setup grpc connection + defer close
			conn, err := DialClientGRPCServer(ctx, daemonAddr)
			if err != nil {
				return fmt.Errorf("connect to service CLI interface: %w", err)
			}
			defer conn.Close()
			client := proto.NewDaemonServiceClient(conn)

			// daemon login
			if err := doDaemonLogin(ctx, cmd, client, activeProf, pm, &profilemanager.ConfigInput{}); err != nil {
				return fmt.Errorf("daemon login failed: %v", err)
			}
		}

		cmd.Println("Logged in successfully")

		return nil
	},
}

func doDaemonLogin(ctx context.Context, cmd *cobra.Command, client proto.DaemonServiceClient, activeProf *profilemanager.Profile, pm *profilemanager.ProfileManager, ic *profilemanager.ConfigInput) error {
	// get user
	user, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %v", err)
	}

	// setup daemon
	alreadyConnected, err := daemonSetup(ctx, cmd, client, activeProf, ic, user.Username)
	if err != nil {
		return fmt.Errorf("daemon setup failed: %v", err)
	}

	if alreadyConnected {
		return nil
	}

	// login
	if err := daemonLogin(ctx, cmd, client, activeProf, pm, ic, user.Username); err != nil {
		return fmt.Errorf("daemon login failed: %v", err)
	}

	return nil
}

func daemonSetup(ctx context.Context, cmd *cobra.Command, client proto.DaemonServiceClient, activeProf *profilemanager.Profile, ic *profilemanager.ConfigInput, username string) (bool, error) {
	// Check if deprecated config flag is set and show warning
	if cmd.Flag("config").Changed && configPath != "" {
		cmd.PrintErrf("Warning: Config flag is deprecated, it should be set as a service argument with $NB_CONFIG environment or with \"-config\" flag; netbird service reconfigure --service-env=\"NB_CONFIG=<file_path>\" or netbird service run --config=<file_path>\n")
	}

	status, err := client.Status(ctx, &proto.StatusRequest{
		WaitForReady: func() *bool { b := true; return &b }(),
	})
	if err != nil {
		return false, fmt.Errorf("unable to get daemon status: %v", err)
	}

	if status.Status == string(internal.StatusConnected) {
		// if non-empty profileName, this means that we switched profile
		profileSwitched := profileName != ""
		if !profileSwitched {
			return true, nil
		}

		// we are already connected, but we want to switch profiles
		// so we need to disconnect first
		if _, err := client.Down(ctx, &proto.DownRequest{}); err != nil {
			log.Errorf("call service down method: %v", err)
			return false, err
		}
	}

	// set default values for setconfigreq
	setConfigReq := configInputToSetConfigRequest(ic)
	setConfigReq.ProfileName = activeProf.Name
	setConfigReq.Username = username
	setConfigReq.ManagementUrl = managementURL
	setConfigReq.AdminURL = adminURL
	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		setConfigReq.OptionalPreSharedKey = &preSharedKey
	}

	// set the new config
	if _, err := client.SetConfig(ctx, setConfigReq); err != nil {
		if st, ok := gstatus.FromError(err); ok && st.Code() == codes.Unavailable {
			log.Warnf("setConfig method is not available in the daemon")
		} else {
			return false, fmt.Errorf("call service setConfig method: %v", err)
		}
	}

	return false, nil
}

func daemonLogin(ctx context.Context, cmd *cobra.Command, client proto.DaemonServiceClient, activeProf *profilemanager.Profile, pm *profilemanager.ProfileManager, ic *profilemanager.ConfigInput, username string) error {
	providedSetupKey, err := getSetupKey()
	if err != nil {
		return err
	}

	// set standard variables for login request
	loginReq := configInputToLoginRequest(ic)
	loginReq.SetupKey = providedSetupKey
	loginReq.ManagementUrl = managementURL
	loginReq.IsUnixDesktopClient = isUnixRunningDesktop()
	loginReq.Hostname = hostName
	loginReq.ProfileName = &activeProf.Name
	loginReq.Username = &username

	profileState, err := pm.GetProfileState(activeProf.Name)
	if err != nil {
		log.Debugf("failed to get profile state for login hint: %v", err)
	} else if profileState.Email != "" {
		loginReq.Hint = &profileState.Email
	}

	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		loginReq.OptionalPreSharedKey = &preSharedKey
	}

	var loginErr error
	var loginResp *proto.LoginResponse
	err = WithBackOff(func() error {
		var backOffErr error
		loginResp, backOffErr = client.Login(ctx, loginReq)
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

	return nil
}

func getActiveProfile(ctx context.Context, pm *profilemanager.ProfileManager, profileName string, username string) (*profilemanager.Profile, error) {
	// switch profile if provided
	if profileName != "" {
		if err := switchProfileOnDaemon(ctx, pm, profileName, username); err != nil {
			return nil, fmt.Errorf("switch profile: %v", err)
		}
	}

	activeProf, err := pm.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %v", err)
	}

	if activeProf == nil {
		return nil, fmt.Errorf("active profile not found, please run 'netbird profile create' first")
	}
	return activeProf, nil
}

func switchProfileOnDaemon(ctx context.Context, pm *profilemanager.ProfileManager, profileName string, username string) error {
	err := switchProfile(ctx, profileName, username)
	if err != nil {
		return fmt.Errorf("switch profile on daemon: %v", err)
	}

	err = pm.SwitchProfile(profileName)
	if err != nil {
		return fmt.Errorf("switch profile: %v", err)
	}

	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		log.Errorf("failed to connect to service CLI interface %v", err)
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)

	status, err := client.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("unable to get daemon status: %v", err)
	}

	if status.Status == string(internal.StatusConnected) {
		if _, err := client.Down(ctx, &proto.DownRequest{}); err != nil {
			log.Errorf("call service down method: %v", err)
			return err
		}
	}

	return nil
}

func switchProfile(ctx context.Context, profileName string, username string) error {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		//nolint
		return fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)

	_, err = client.SwitchProfile(ctx, &proto.SwitchProfileRequest{
		ProfileName: &profileName,
		Username:    &username,
	})
	if err != nil {
		return fmt.Errorf("switch profile failed: %v", err)
	}

	return nil
}

func doForegroundLogin(ctx context.Context, cmd *cobra.Command, activeProf *profilemanager.Profile, ic *profilemanager.ConfigInput) (*profilemanager.Config, error) {
	// override the default profile filepath if provided
	if configPath != "" {
		_ = profilemanager.NewServiceManager(configPath)
	}

	err := handleRebrand(cmd)
	if err != nil {
		return nil, err
	}

	// update host's static platform and system information
	system.UpdateStaticInfoAsync()

	configFilePath, err := activeProf.FilePath()
	if err != nil {
		return nil, fmt.Errorf("get active profile file path: %v", err)
	}

	// update config with root flags
	ic.ManagementURL = managementURL
	ic.ConfigPath = configFilePath
	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		ic.PreSharedKey = &preSharedKey
	}

	config, err := profilemanager.UpdateOrCreateConfig(*ic)
	if err != nil {
		return nil, fmt.Errorf("get config file: %v", err)
	}

	_, _ = profilemanager.UpdateOldManagementURL(ctx, config, configFilePath)

	providedSetupKey, err := getSetupKey()
	if err != nil {
		return nil, err
	}

	err = foregroundLogin(ctx, cmd, config, providedSetupKey, activeProf.Name)
	if err != nil {
		return nil, fmt.Errorf("foreground login failed: %v", err)
	}

	return config, nil
}

func handleSSOLogin(ctx context.Context, cmd *cobra.Command, loginResp *proto.LoginResponse, client proto.DaemonServiceClient, pm *profilemanager.ProfileManager) error {
	openURL(cmd, loginResp.VerificationURIComplete, loginResp.UserCode, noBrowser)

	resp, err := client.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode, Hostname: hostName})
	if err != nil {
		return fmt.Errorf("waiting sso login failed with: %v", err)
	}

	if resp.Email != "" {
		err = pm.SetActiveProfileState(&profilemanager.ProfileState{
			Email: resp.Email,
		})
		if err != nil {
			log.Warnf("failed to set active profile email: %v", err)
		}
	}

	return nil
}

func foregroundLogin(ctx context.Context, cmd *cobra.Command, config *profilemanager.Config, setupKey, profileName string) error {
	authClient, err := auth.NewAuth(ctx, config.PrivateKey, config.ManagementURL, config)
	if err != nil {
		return fmt.Errorf("failed to create auth client: %v", err)
	}
	defer authClient.Close()

	needsLogin := false

	err, isAuthError := authClient.Login(ctx, "", "")
	if isAuthError {
		needsLogin = true
	} else if err != nil {
		return fmt.Errorf("login check failed: %v", err)
	}

	jwtToken := ""
	if setupKey == "" && needsLogin {
		tokenInfo, err := foregroundGetTokenInfo(ctx, cmd, config, profileName)
		if err != nil {
			return fmt.Errorf("interactive sso login failed: %v", err)
		}
		jwtToken = tokenInfo.GetTokenToUse()
	}

	err, _ = authClient.Login(ctx, setupKey, jwtToken)
	if err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	return nil
}

func foregroundGetTokenInfo(ctx context.Context, cmd *cobra.Command, config *profilemanager.Config, profileName string) (*auth.TokenInfo, error) {
	hint := ""
	pm := profilemanager.NewProfileManager()
	profileState, err := pm.GetProfileState(profileName)
	if err != nil {
		log.Debugf("failed to get profile state for login hint: %v", err)
	} else if profileState.Email != "" {
		hint = profileState.Email
	}

	oAuthFlow, err := auth.NewOAuthFlow(ctx, config, isUnixRunningDesktop(), false, hint)
	if err != nil {
		return nil, err
	}

	flowInfo, err := oAuthFlow.RequestAuthInfo(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting a request OAuth flow info failed: %v", err)
	}

	openURL(cmd, flowInfo.VerificationURIComplete, flowInfo.UserCode, noBrowser)

	tokenInfo, err := oAuthFlow.WaitToken(context.TODO(), flowInfo)
	if err != nil {
		return nil, fmt.Errorf("waiting for browser login failed: %v", err)
	}

	return &tokenInfo, nil
}

func openURL(cmd *cobra.Command, verificationURIComplete, userCode string, noBrowser bool) {
	var codeMsg string
	if userCode != "" && !strings.Contains(verificationURIComplete, userCode) {
		codeMsg = fmt.Sprintf("and enter the code %s to authenticate.", userCode)
	}

	if noBrowser {
		cmd.Println("Use this URL to log in:\n\n" + verificationURIComplete + " " + codeMsg)
	} else {
		cmd.Println("Please do the SSO login in your browser. \n" +
			"If your browser didn't open automatically, use this URL to log in:\n\n" +
			verificationURIComplete + " " + codeMsg)
	}

	cmd.Println("")

	if !noBrowser {
		if err := util.OpenBrowser(verificationURIComplete); err != nil {
			cmd.Println("\nAlternatively, you may want to use a setup key, see:\n\n" +
				"https://docs.netbird.io/how-to/register-machines-using-setup-keys")
		}
	}
}

// isUnixRunningDesktop checks if a Linux OS is running desktop environment
func isUnixRunningDesktop() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		return false
	}
	return os.Getenv("DESKTOP_SESSION") != "" || os.Getenv("XDG_CURRENT_DESKTOP") != ""
}

func setEnvAndFlags(cmd *cobra.Command) error {
	SetFlagsFromEnvVars(rootCmd)

	cmd.SetOut(cmd.OutOrStdout())

	err := util.InitLog(logLevel, "console")
	if err != nil {
		return fmt.Errorf("failed initializing log %v", err)
	}

	return nil
}

func configInputToSetConfigRequest(ic *profilemanager.ConfigInput) *proto.SetConfigRequest {
	req := &proto.SetConfigRequest{
		ManagementUrl:                 ic.ManagementURL,
		AdminURL:                      ic.AdminURL,
		NatExternalIPs:                ic.NATExternalIPs,
		ExtraIFaceBlacklist:           ic.ExtraIFaceBlackList,
		CustomDNSAddress:              ic.CustomDNSAddress,
		DnsLabels:                     ic.DNSLabels.ToPunycodeList(),
		CleanDNSLabels:                ic.DNSLabels != nil && len(ic.DNSLabels) == 0,
		CleanNATExternalIPs:           ic.NATExternalIPs != nil && len(ic.NATExternalIPs) == 0,
		RosenpassEnabled:              ic.RosenpassEnabled,
		RosenpassPermissive:           ic.RosenpassPermissive,
		ServerSSHAllowed:              ic.ServerSSHAllowed,
		EnableSSHRoot:                 ic.EnableSSHRoot,
		EnableSSHSFTP:                 ic.EnableSSHSFTP,
		EnableSSHLocalPortForwarding:  ic.EnableSSHLocalPortForwarding,
		EnableSSHRemotePortForwarding: ic.EnableSSHRemotePortForwarding,
		DisableSSHAuth:                ic.DisableSSHAuth,
		InterfaceName:                 ic.InterfaceName,
		NetworkMonitor:                ic.NetworkMonitor,
		DisableAutoConnect:            ic.DisableAutoConnect,
		DisableClientRoutes:           ic.DisableClientRoutes,
		DisableServerRoutes:           ic.DisableServerRoutes,
		DisableDns:                    ic.DisableDNS,
		DisableFirewall:               ic.DisableFirewall,
		BlockLanAccess:                ic.BlockLANAccess,
		BlockInbound:                  ic.BlockInbound,
		DisableNotifications:          ic.DisableNotifications,
		LazyConnectionEnabled:         ic.LazyConnectionEnabled,
		OptionalPreSharedKey:          ic.PreSharedKey,
	}

	// Type conversions needed
	if ic.WireguardPort != nil {
		p := int64(*ic.WireguardPort)
		req.WireguardPort = &p
	}
	if ic.MTU != nil {
		m := int64(*ic.MTU)
		req.Mtu = &m
	}
	if ic.SSHJWTCacheTTL != nil {
		ttl := int32(*ic.SSHJWTCacheTTL)
		req.SshJWTCacheTTL = &ttl
	}
	if ic.DNSRouteInterval != nil {
		req.DnsRouteInterval = durationpb.New(*ic.DNSRouteInterval)
	}

	return req
}

func configInputToLoginRequest(ic *profilemanager.ConfigInput) *proto.LoginRequest {
	req := &proto.LoginRequest{
		ManagementUrl:                 ic.ManagementURL,
		AdminURL:                      ic.AdminURL,
		NatExternalIPs:                ic.NATExternalIPs,
		CleanNATExternalIPs:           ic.NATExternalIPs != nil && len(ic.NATExternalIPs) == 0,
		ExtraIFaceBlacklist:           ic.ExtraIFaceBlackList,
		CustomDNSAddress:              ic.CustomDNSAddress,
		DnsLabels:                     ic.DNSLabels.ToPunycodeList(),
		CleanDNSLabels:                ic.DNSLabels != nil && len(ic.DNSLabels) == 0,
		RosenpassEnabled:              ic.RosenpassEnabled,
		RosenpassPermissive:           ic.RosenpassPermissive,
		ServerSSHAllowed:              ic.ServerSSHAllowed,
		EnableSSHRoot:                 ic.EnableSSHRoot,
		EnableSSHSFTP:                 ic.EnableSSHSFTP,
		EnableSSHLocalPortForwarding:  ic.EnableSSHLocalPortForwarding,
		EnableSSHRemotePortForwarding: ic.EnableSSHRemotePortForwarding,
		DisableSSHAuth:                ic.DisableSSHAuth,
		InterfaceName:                 ic.InterfaceName,
		NetworkMonitor:                ic.NetworkMonitor,
		DisableAutoConnect:            ic.DisableAutoConnect,
		DisableClientRoutes:           ic.DisableClientRoutes,
		DisableServerRoutes:           ic.DisableServerRoutes,
		DisableDns:                    ic.DisableDNS,
		DisableFirewall:               ic.DisableFirewall,
		BlockLanAccess:                ic.BlockLANAccess,
		BlockInbound:                  ic.BlockInbound,
		DisableNotifications:          ic.DisableNotifications,
		LazyConnectionEnabled:         ic.LazyConnectionEnabled,
		OptionalPreSharedKey:          ic.PreSharedKey,
	}

	// Type conversions needed
	if ic.WireguardPort != nil {
		p := int64(*ic.WireguardPort)
		req.WireguardPort = &p
	}
	if ic.MTU != nil {
		m := int64(*ic.MTU)
		req.Mtu = &m
	}
	if ic.SSHJWTCacheTTL != nil {
		ttl := int32(*ic.SSHJWTCacheTTL)
		req.SshJWTCacheTTL = &ttl
	}
	if ic.DNSRouteInterval != nil {
		req.DnsRouteInterval = durationpb.New(*ic.DNSRouteInterval)
	}

	return req
}
