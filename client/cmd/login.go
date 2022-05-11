package cmd

import (
	"context"
	"fmt"
	"github.com/skratchdot/open-golang/open"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"time"

	"github.com/netbirdio/netbird/util"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login to the Wiretrustee Management Service (first run)",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, "console")
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx := internal.CtxInitState(context.Background())

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, adminURL, configPath, preSharedKey)
			if err != nil {
				log.Errorf("get config file: %v", err)
				return err
			}

			err = foregroundLogin(ctx, config, setupKey)
			if err != nil {
				log.Errorf("foreground login failed: %v", err)
				return err
			}
			return nil
		}

		jwtToken := ""

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		client := proto.NewDaemonServiceClient(conn)

		status, err := client.Status(ctx, &proto.StatusRequest{})
		if err != nil {
			log.Errorf("unable to get daemon status: %v", err)
			return err
		}

		if setupKey == "" && status.Status == string(internal.StatusNeedsLogin) {
			tokenInfo, err := daemonGetTokenInfo(ctx, client)
			if err != nil {
				log.Errorf("interactive sso login failed: %v", err)
				return err
			}
			jwtToken = tokenInfo.AccessToken
		}

		request := proto.LoginRequest{
			SetupKey:      setupKey,
			PreSharedKey:  preSharedKey,
			ManagementUrl: managementURL,
			JwtToken:      jwtToken,
		}

		err = WithBackOff(func() error {
			if _, err := client.Login(ctx, &request); err != nil {
				log.Errorf("try login: %v", err)
			}
			return err
		})
		if err != nil {
			log.Errorf("backoff cycle failed: %v", err)
		}
		return err
	},
}

func foregroundLogin(ctx context.Context, config *internal.Config, setupKey string) error {
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
		log.Errorf("backoff cycle failed: %v", err)
		return err
	}

	jwtToken := ""
	if setupKey == "" && needsLogin {
		tokenInfo, err := foregroundGetTokenInfo(ctx, config)
		if err != nil {
			log.Errorf("interactive sso login failed: %v", err)
			return err
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
		log.Errorf("backoff cycle failed: %v", err)
		return err
	}

	return nil
}

func foregroundGetTokenInfo(ctx context.Context, config *internal.Config) (*internal.TokenInfo, error) {

	providerConfig, err := internal.GetDeviceAuthorizationFlowInfo(ctx, config)
	if err != nil {
		if s, ok := gstatus.FromError(err); ok && s.Code() == codes.NotFound {
			return nil, fmt.Errorf("no SSO provider returned from management. " +
				"If you are using hosting Netbird see documentation at " +
				"https://github.com/netbirdio/netbird/tree/main/management for details")
		}
		log.Errorf("getting device authorization flow info failed with error: %v", err)
		return nil, err
	}

	hostedClient := internal.NewHostedDeviceFlow(
		providerConfig.ProviderConfig.Audience,
		providerConfig.ProviderConfig.ClientID,
		providerConfig.ProviderConfig.Domain,
	)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		log.Errorf("getting a request device code failed: %v", err)
		return nil, err
	}

	openURL(flowInfo.VerificationURI, flowInfo.VerificationURIComplete, flowInfo.UserCode)

	waitTimeout := time.Duration(flowInfo.ExpiresIn)
	waitCTX, c := context.WithTimeout(context.TODO(), waitTimeout*time.Second)
	defer c()

	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		log.Errorf("waiting for browser login failed: %v", err)
		return nil, err
	}

	return &tokenInfo, nil
}

func daemonGetTokenInfo(ctx context.Context, client proto.DaemonServiceClient) (*internal.TokenInfo, error) {

	cfg, err := client.GetConfig(ctx, &proto.GetConfigRequest{})
	if err != nil {
		log.Errorf("get config settings from server: %v", err)
		return nil, err
	}

	if cfg.DeviceAuthorizationFlow == nil {
		return nil, fmt.Errorf("no SSO provider returned from management. " +
			"If you are using hosting Netbird see documentation at " +
			"https://github.com/netbirdio/netbird/tree/main/management for details")
	}

	providerConfig := cfg.DeviceAuthorizationFlow.GetProviderConfig()

	hostedClient := internal.NewHostedDeviceFlow(
		providerConfig.Audience,
		providerConfig.ClientID,
		providerConfig.Domain,
	)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		log.Errorf("getting a request device code failed: %v", err)
		return nil, err
	}

	openURL(flowInfo.VerificationURI, flowInfo.VerificationURIComplete, flowInfo.UserCode)

	waitTimeout := time.Duration(flowInfo.ExpiresIn)
	waitCTX, c := context.WithTimeout(context.TODO(), waitTimeout*time.Second)
	defer c()

	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		log.Errorf("waiting for browser login failed: %v", err)
		return nil, err
	}

	return &tokenInfo, nil
}

func openURL(verificationURI, verificationURIComplete, userCode string) {
	err := open.Run(verificationURIComplete)
	if err != nil {
		fmt.Println("Unable to open the default browser.")
		fmt.Println("If this is not an interactive shell, you may want to use the setup key, see https://www.netbird.io/docs/overview/setup-keys")
		fmt.Printf("Otherwise, you can continue the login flow by accessing the url below:\n\t%s\n", verificationURI)
		fmt.Printf("Use the access code: %s\n", userCode)
		fmt.Printf("Or press CTRL + C or COMMAND + C")
	}
}
