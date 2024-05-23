package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/util"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login to the Netbird Management Service (first run)",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := util.InitLog(logLevel, "console")
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx := internal.CtxInitState(context.Background())

		if hostName != "" {
			// nolint
			ctx = context.WithValue(ctx, system.DeviceNameCtxKey, hostName)
		}

		// workaround to run without service
		if logFile == "console" {
			err = handleRebrand(cmd)
			if err != nil {
				return err
			}

			ic := internal.ConfigInput{
				ManagementURL: managementURL,
				AdminURL:      adminURL,
				ConfigPath:    configPath,
			}
			if rootCmd.PersistentFlags().Changed(preSharedKeyFlag) {
				ic.PreSharedKey = &preSharedKey
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
			cmd.Println("Logging successfully")
			return nil
		}

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to daemon error: %v\n"+
				"If the daemon is not running please run: "+
				"\nnetbird service install \nnetbird service start\n", err)
		}
		defer conn.Close()

		client := proto.NewDaemonServiceClient(conn)

		loginRequest := proto.LoginRequest{
			SetupKey:             setupKey,
			ManagementUrl:        managementURL,
			IsLinuxDesktopClient: isLinuxRunningDesktop(),
			Hostname:             hostName,
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
			openURL(cmd, loginResp.VerificationURIComplete, loginResp.UserCode)

			_, err = client.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode, Hostname: hostName})
			if err != nil {
				return fmt.Errorf("waiting sso login failed with: %v", err)
			}
		}

		cmd.Println("Logging successfully")

		return nil
	},
}

func foregroundLogin(ctx context.Context, cmd *cobra.Command, config *internal.Config, setupKey string) error {
	needsLogin := false

	err := WithBackOff(func() error {
		err := internal.Login(ctx, config, "", "")
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			needsLogin = true
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	jwtToken := ""
	if setupKey == "" && needsLogin {
		tokenInfo, err := foregroundGetTokenInfo(ctx, cmd, config)
		if err != nil {
			return fmt.Errorf("interactive sso login failed: %v", err)
		}
		jwtToken = tokenInfo.GetTokenToUse()
	}

	var lastError error

	err = WithBackOff(func() error {
		err := internal.Login(ctx, config, setupKey, jwtToken)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			lastError = err
			return nil
		}
		return err
	})

	if lastError != nil {
		return fmt.Errorf("login failed: %v", lastError)
	}

	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	return nil
}

func foregroundGetTokenInfo(ctx context.Context, cmd *cobra.Command, config *internal.Config) (*auth.TokenInfo, error) {
	oAuthFlow, err := auth.NewOAuthFlow(ctx, config, isLinuxRunningDesktop())
	if err != nil {
		return nil, err
	}

	flowInfo, err := oAuthFlow.RequestAuthInfo(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting a request OAuth flow info failed: %v", err)
	}

	openURL(cmd, flowInfo.VerificationURIComplete, flowInfo.UserCode)

	waitTimeout := time.Duration(flowInfo.ExpiresIn) * time.Second
	waitCTX, c := context.WithTimeout(context.TODO(), waitTimeout)
	defer c()

	tokenInfo, err := oAuthFlow.WaitToken(waitCTX, flowInfo)
	if err != nil {
		return nil, fmt.Errorf("waiting for browser login failed: %v", err)
	}

	return &tokenInfo, nil
}

func openURL(cmd *cobra.Command, verificationURIComplete, userCode string) {
	var codeMsg string
	if userCode != "" && !strings.Contains(verificationURIComplete, userCode) {
		codeMsg = fmt.Sprintf("and enter the code %s to authenticate.", userCode)
	}

	cmd.Println("Please do the SSO login in your browser. \n" +
		"If your browser didn't open automatically, use this URL to log in:\n\n" +
		verificationURIComplete + " " + codeMsg)
	cmd.Println("")
	if err := open.Run(verificationURIComplete); err != nil {
		cmd.Println("\nAlternatively, you may want to use a setup key, see:\n\n" +
			"https://docs.netbird.io/how-to/register-machines-using-setup-keys")
	}
}

// isLinuxRunningDesktop checks if a Linux OS is running desktop environment
func isLinuxRunningDesktop() bool {
	return os.Getenv("DESKTOP_SESSION") != "" || os.Getenv("XDG_CURRENT_DESKTOP") != ""
}
