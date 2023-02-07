package cmd

import (
	"context"
	"fmt"
	"github.com/skratchdot/open-golang/open"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"time"

	"github.com/netbirdio/netbird/util"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
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

		// workaround to run without service
		if logFile == "console" {
			err = handleRebrand(cmd)
			if err != nil {
				return err
			}

			config, err := internal.GetConfig(internal.ConfigInput{
				ManagementURL: managementURL,
				AdminURL:      adminURL,
				ConfigPath:    configPath,
				PreSharedKey:  &preSharedKey,
			})
			if err != nil {
				return fmt.Errorf("get config file: %v", err)
			}

			config, _ = internal.UpdateOldManagementPort(ctx, config, configPath)

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
			SetupKey:      setupKey,
			PreSharedKey:  preSharedKey,
			ManagementUrl: managementURL,
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
			openURL(cmd, loginResp.VerificationURIComplete)

			_, err = client.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode})
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
		jwtToken = tokenInfo.AccessToken
	}

	err = WithBackOff(func() error {
		err := internal.Login(ctx, config, setupKey, jwtToken)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	return nil
}

func foregroundGetTokenInfo(ctx context.Context, cmd *cobra.Command, config *internal.Config) (*internal.TokenInfo, error) {
	providerConfig, err := internal.GetDeviceAuthorizationFlowInfo(ctx, config)
	if err != nil {
		s, ok := gstatus.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return nil, fmt.Errorf("no SSO provider returned from management. " +
				"If you are using hosting Netbird see documentation at " +
				"https://github.com/netbirdio/netbird/tree/main/management for details")
		} else if ok && s.Code() == codes.Unimplemented {
			mgmtURL := managementURL
			if mgmtURL == "" {
				mgmtURL = internal.DefaultManagementURL
			}
			return nil, fmt.Errorf("the management server, %s, does not support SSO providers, "+
				"please update your servver or use Setup Keys to login", mgmtURL)
		} else {
			return nil, fmt.Errorf("getting device authorization flow info failed with error: %v", err)
		}
	}

	hostedClient := internal.NewHostedDeviceFlow(
		providerConfig.ProviderConfig.Audience,
		providerConfig.ProviderConfig.ClientID,
		providerConfig.ProviderConfig.TokenEndpoint,
		providerConfig.ProviderConfig.DeviceAuthEndpoint,
	)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting a request device code failed: %v", err)
	}

	openURL(cmd, flowInfo.VerificationURIComplete)

	waitTimeout := time.Duration(flowInfo.ExpiresIn)
	waitCTX, c := context.WithTimeout(context.TODO(), waitTimeout*time.Second)
	defer c()

	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		return nil, fmt.Errorf("waiting for browser login failed: %v", err)
	}

	return &tokenInfo, nil
}

func openURL(cmd *cobra.Command, verificationURIComplete string) {
	err := open.Run(verificationURIComplete)
	cmd.Printf("Please do the SSO login in your browser. \n" +
		"If your browser didn't open automatically, use this URL to log in:\n\n" +
		" " + verificationURIComplete + " \n\n")
	if err != nil {
		cmd.Printf("Alternatively, you may want to use a setup key, see:\n\n https://www.netbird.io/docs/overview/setup-keys\n")
	}
}
