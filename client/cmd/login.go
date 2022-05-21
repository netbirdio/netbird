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
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, "console")
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx := internal.CtxInitState(context.Background())

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, adminURL, configPath, preSharedKey)
			if err != nil {
				return fmt.Errorf("get config file: %v", err)
			}

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
			openURL(cmd, loginResp.VerificationURI, loginResp.VerificationURIComplete, loginResp.UserCode)

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
				mgmtURL = internal.ManagementURLDefault().String()
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
		providerConfig.ProviderConfig.Domain,
	)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting a request device code failed: %v", err)
	}

	openURL(cmd, flowInfo.VerificationURI, flowInfo.VerificationURIComplete, flowInfo.UserCode)

	waitTimeout := time.Duration(flowInfo.ExpiresIn)
	waitCTX, c := context.WithTimeout(context.TODO(), waitTimeout*time.Second)
	defer c()

	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		return nil, fmt.Errorf("waiting for browser login failed: %v", err)
	}

	return &tokenInfo, nil
}

func openURL(cmd *cobra.Command, verificationURI, verificationURIComplete, userCode string) {
	err := open.Run(verificationURIComplete)
	if err != nil {
		cmd.Println("Unable to open the default browser.")
		cmd.Println("If this is not an interactive shell, you may want to use the setup key, see https://www.netbird.io/docs/overview/setup-keys")
		cmd.Printf("Otherwise, you can continue the login flow by accessing the url below:\n\t%s\n", verificationURI)
		cmd.Printf("Use the access code: %s\n", userCode)
		cmd.Println("Or press CTRL + C or COMMAND + C")
	}
}
