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

		ctx := internal.CtxInitState(context.Background())

		if hostName != "" {
			// nolint
			ctx = context.WithValue(ctx, system.DeviceNameCtxKey, hostName)
		}
		username, err := user.Current()
		if err != nil {
			return fmt.Errorf("get current user: %v", err)
		}

		pm := profilemanager.NewProfileManager()

		activeProf, err := getActiveProfile(cmd.Context(), pm, profileName, username.Username)
		if err != nil {
			return fmt.Errorf("get active profile: %v", err)
		}

		providedSetupKey, err := getSetupKey()
		if err != nil {
			return err
		}

		// workaround to run without service
		if util.FindFirstLogPath(logFiles) == "" {
			if err := doForegroundLogin(ctx, cmd, providedSetupKey, activeProf); err != nil {
				return fmt.Errorf("foreground login failed: %v", err)
			}
			return nil
		}

		if err := doDaemonLogin(ctx, cmd, providedSetupKey, activeProf, username.Username, pm); err != nil {
			return fmt.Errorf("daemon login failed: %v", err)
		}

		cmd.Println("Logging successfully")

		return nil
	},
}

func doDaemonLogin(ctx context.Context, cmd *cobra.Command, providedSetupKey string, activeProf *profilemanager.Profile, username string, pm *profilemanager.ProfileManager) error {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		//nolint
		return fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)

	var dnsLabelsReq []string
	if dnsLabelsValidated != nil {
		dnsLabelsReq = dnsLabelsValidated.ToSafeStringList()
	}

	loginRequest := proto.LoginRequest{
		SetupKey:            providedSetupKey,
		ManagementUrl:       managementURL,
		IsUnixDesktopClient: isUnixRunningDesktop(),
		Hostname:            hostName,
		DnsLabels:           dnsLabelsReq,
		ProfileName:         &activeProf.Name,
		Username:            &username,
	}

	profileState, err := pm.GetProfileState(activeProf.Name)
	if err != nil {
		log.Debugf("failed to get profile state for login hint: %v", err)
	} else if profileState.Email != "" {
		loginRequest.Hint = &profileState.Email
	}

	if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
		loginRequest.OptionalPreSharedKey = &preSharedKey
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
	err := switchProfile(context.Background(), profileName, username)
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

func doForegroundLogin(ctx context.Context, cmd *cobra.Command, setupKey string, activeProf *profilemanager.Profile) error {

	err := handleRebrand(cmd)
	if err != nil {
		return err
	}

	// update host's static platform and system information
	system.UpdateStaticInfoAsync()

	configFilePath, err := activeProf.FilePath()
	if err != nil {
		return fmt.Errorf("get active profile file path: %v", err)

	}

	config, err := profilemanager.ReadConfig(configFilePath)
	if err != nil {
		return fmt.Errorf("read config file %s: %v", configFilePath, err)
	}

	err = foregroundLogin(ctx, cmd, config, setupKey, activeProf.Name)
	if err != nil {
		return fmt.Errorf("foreground login failed: %v", err)
	}
	cmd.Println("Logging successfully")
	return nil
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
